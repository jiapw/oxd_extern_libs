#pragma once

#include <string>
#include <iostream>
#include <regex>
#include <thread>
#include <chrono>

#include <future>

#include <boost/unordered/concurrent_flat_map.hpp>
#include <map>
#include <boost/algorithm/string.hpp>

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>

namespace simple{

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace ssl	= boost::asio::ssl;
namespace http	= boost::beast::http;


// Enum to define your custom error codes
enum class http_error_code {
	invalid_url = 0x1001,
	invalid_request,

	timeout_resolve = 0x2001,
	timeout_connect,
	timeout_ssl_handshake,
	timeout_write,
	timeout_read,

};

class http_error_category : public boost::system::error_category
{
public:
	const char* name() const noexcept override
	{
		return "simple_http_error_category";
	}

	std::string message(int ev) const override
	{
		switch (static_cast<http_error_code>(ev))
		{
		case http_error_code::invalid_url:
			return "url is invalid";
		case http_error_code::invalid_request:
			return "request is invalid";
		case http_error_code::timeout_resolve:
			return "resolve timeout";
		case http_error_code::timeout_connect:
			return "connect timeout";
		case http_error_code::timeout_ssl_handshake:
			return "ssl handshake timeout";
		case http_error_code::timeout_write:
			return "write timeout";
		case http_error_code::timeout_read:
			return "read timeout";
		default:
			return "unknown error ";
		}
	}

	static beast::error_code make_error_code(http_error_code e) {
		static http_error_category category;
		return beast::error_code(static_cast<int>(e), category);
	}
	
	#define EC_DEFINE(id) static beast::error_code ec_##id() {return make_error_code(http_error_code::id);}
	EC_DEFINE(invalid_url)
	EC_DEFINE(invalid_request)
	EC_DEFINE(timeout_resolve)
	EC_DEFINE(timeout_connect)
	EC_DEFINE(timeout_ssl_handshake)
	EC_DEFINE(timeout_write)
	#undef EC_DEFINE
	/*
	static beast::error_code ec_invalid_url()
	{
		return make_error_code(http_error_code::invalid_url);
	}
	static beast::error_code ec_invalid_request()
	{
		return make_error_code(http_error_code::invalid_request);
	}
	static beast::error_code ec_timeout_resolve()
	{
		return make_error_code(http_error_code::timeout_resolve);
	}
	static beast::error_code ec_timeout_connect()
	{
		return make_error_code(http_error_code::timeout_connect);
	}
	static beast::error_code ec_timeout_ssl_handshake()
	{
		return make_error_code(http_error_code::timeout_ssl_handshake);
	}
	static beast::error_code ec_timeout_connect()
	{
		return make_error_code(http_error_code::timeout_connect);
	}
	*/
};



struct memory_block_1m
{
	char data[1024 * 1024];
};

struct http_url
{
	std::string scheme;
	std::string host;
	std::string port;
	std::string path;
	std::string query;
	std::string fragment;

	void clear()
	{
		scheme.clear();
		host.clear();
		port.clear();
		path.clear();
		query.clear();
		fragment.clear();
	}
	bool valid()
	{
		return (
			scheme.length() &&
			host.length() &&
			port.length() &&
			path.length()
		);
	}
	std::string target() const
	{
		if (query.length())
			return path + "?" + query;
		else
			return path;
	}

	bool parse(const std::string& url)
	{
		return parse(url, *this);
	}

	static bool parse(const std::string& url, http_url& out)
	{
		std::regex url_regex(R"(([^:]+):\/\/([^\/:]+)(?::(\d+))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?)");
		std::smatch url_match;

		if (std::regex_match(url, url_match, url_regex))
		{
			out.scheme = url_match[1].str();
			boost::to_lower(out.scheme);

			out.host = url_match[2].str();
			boost::to_lower(out.host);

			out.port = url_match[3].str();
			if (out.port.length() == 0)
			{
				if (out.scheme == "https")
					out.port = "443";
				else if (out.scheme == "http")
					out.port = "80";
			}

			out.path = url_match[4].str();
			if (out.path.length() == 0)
				out.path = "/";

			out.query = url_match[5].str();
			out.fragment = url_match[6].str();

			return true;
		}
		else {
			// std::cerr << "Invalid URL format: " << url << std::endl;
			return false;
		}
	}
};

struct http_request // : public std::enable_shared_from_this<http_request>
{
	struct limit_value
	{
		uint16_t resolve_timeout = 5 * 1000;
		uint16_t connect_timeout = 5 * 1000;
		uint16_t handshake_timeout = 5 * 1000;
		uint16_t write_timeout = 5 * 1000;
		uint16_t read_response_header_timeout = 5 * 1000;
		uint16_t read_response_body_timeout = 10 * 1000;
		uint16_t read_response_chunk_timeout = 2 * 1000;

		uint64_t string_body_limit = 32 * 1024 * 1024;
	};

	limit_value limited;

	volatile bool ended = true;

	int version = 11; // http 1.1
	
	http_url url;

	http::request<http::empty_body> req;

	http::response_parser<http::string_body> res_string_body;

	http::response_parser<http::buffer_body> res_buffer_body;
	char chunk_buffer[1024*10];
	void* call_back = nullptr;

	beast::error_code error_code;

	http_request(const std::string& url, void* call_back)
	{
		res_string_body.body_limit(limited.string_body_limit);
		res_buffer_body.body_limit(std::numeric_limits<std::uint64_t>::max());
		init(url, call_back);
	}
	~http_request()
	{
		return;
	}
	bool init(const std::string& s, void* call_back)
	{
		return init("GET", s, call_back);
	}
	bool init(std::string_view method, const std::string& s, void* call_back)
	{
		ended = false;
		req.clear();
		error_code.clear();
		
		this->call_back = call_back;

		if (!url.parse(s))
		{
			end_in_failure(http_error_category::ec_invalid_url(), "parse url");
			return false;
		}

		req.method_string(method);
		req.version(version);
		req.target(url.target());
		req.set(http::field::host, url.host);

		return true;
	}

	void end_in_failure(const beast::error_code ec, const std::string& info)
	{
		ended = true;
		error_code = ec;
		return fail(ec, info.c_str());
	}

	void end_in_success()
	{
		ended = true;
	}

	static void fail(beast::error_code ec, char const* what)
	{
		std::cerr << what << ": " << ec.message() << "\n";
	}

	static bool fail(char const* message, char const* what)
	{
		std::cerr << what << ": " << message << "\n";
		return false;
	}

};

struct steady_timer_ex : public boost::asio::steady_timer
{
	//std::string timeout_info;
	steady_timer_ex(asio::io_context& ioc_ctx)
		: boost::asio::steady_timer(ioc_ctx)
	{
	}
	template <
		BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code))
		WaitToken = asio::default_completion_token_t<executor_type>>
	void async_wait_ex(int64_t timeout_ms, WaitToken&& token = asio::default_completion_token_t<executor_type>())
	{
		//this->timeout_info = timeout_info;
		this->expires_after(std::chrono::milliseconds(timeout_ms));
		this->async_wait(token);
	}
};

struct http_client : public std::enable_shared_from_this<http_client>
{
	beast::ssl_stream<beast::tcp_stream> ssl_stream_;
	beast::tcp_stream tcp_stream_;
	steady_timer_ex timer;

	asio::ip::tcp::resolver resolver;

	beast::flat_buffer buffer;

	std::shared_ptr<http_request> request; 
	bool is_https_request = false;
	uint64_t content_length = 0;
	uint64_t content_recv = 0;
	
	http_client(asio::io_context& ioc_ctx, ssl::context& ssl_ctx)
		: ssl_stream_(ioc_ctx, ssl_ctx)
		, tcp_stream_(ioc_ctx)
		, resolver(ioc_ctx)
		, timer(ioc_ctx)
	{
	}
	~http_client()
	{
		return;
	}

	inline beast::tcp_stream& get_tcp_stream()
	{
		return is_https_request ? beast::get_lowest_layer(ssl_stream_) : tcp_stream_;
	}

	void execute(std::shared_ptr<http_request> req)
	{
		request = req;
		if (request->ended)
			return request->end_in_failure(http_error_category::ec_invalid_request(), "http_client::execute");

		is_https_request = request->url.scheme == "https";

		buffer.clear();

		if (is_https_request)
		{
			// Set SNI Hostname (many hosts need this to handshake successfully)
			if (!SSL_set_tlsext_host_name(ssl_stream_.native_handle(), request->url.host.c_str()))
			{
				beast::error_code ec{ static_cast<int>(::ERR_get_error()), asio::error::get_ssl_category() };
				return request->end_in_failure(ec, "SSL_set_tlsext_host_name");
			}
		}

		resolver.async_resolve(
			request->url.host,
			request->url.port,
			beast::bind_front_handler(&http_client::on_resolve, shared_from_this())
		);

		
		timer.async_wait_ex( 
			request->limited.resolve_timeout,
			[this](const boost::system::error_code& ec)
			{
				if (ec != boost::asio::error::operation_aborted)
					resolver.cancel(); // cancel async_resolve
			}
		);
	}

	void on_resolve(beast::error_code ec, asio::ip::tcp::resolver::results_type results)
	{
		timer.cancel();

		if (ec)
			return request->end_in_failure(ec, "resolve");

		for (auto& it : results)
		{
			std::cout << it.host_name() << ":" << it.service_name() << " => " << it.endpoint().address() << ":" << it.endpoint().port() << std::endl;
		}

		get_tcp_stream().async_connect(
				results,
				beast::bind_front_handler(&http_client::on_connect, shared_from_this())
		);
		
		timer.async_wait_ex(
			request->limited.connect_timeout,
			[this](const boost::system::error_code& ec)
			{
				if (ec != boost::asio::error::operation_aborted)
				{
					get_tcp_stream().close(); // cancel async_connect
				}
					
			}
		);
	}

	void on_connect(beast::error_code ec, asio::ip::tcp::resolver::results_type::endpoint_type)
	{
		timer.cancel();

		if (ec)
			return request->end_in_failure(ec, "connect");

		if (is_https_request)
		{
			// Perform the SSL handshake
			ssl_stream_.async_handshake(
				ssl::stream_base::client,
				beast::bind_front_handler(&http_client::on_handshake, shared_from_this())
			);

			timer.async_wait_ex(
				request->limited.handshake_timeout,
				[this](const boost::system::error_code& ec)
				{
					if (ec != boost::asio::error::operation_aborted)
						tcp_stream_.close(); // cancel async_connect
				}
			);
		}
		else
		{
			on_handshake(ec);
		}
	}

	void on_handshake(beast::error_code ec)
	{
		timer.cancel();

		if (ec)
			return request->end_in_failure(ec, "handshake");

		if (is_https_request)
		{
			http::async_write(
				ssl_stream_,
				request->req,
				beast::bind_front_handler(&http_client::on_write_request, shared_from_this())
			);

			timer.async_wait_ex(
				request->limited.write_timeout,
				[this](const boost::system::error_code& ec)
				{
					if (ec != boost::asio::error::operation_aborted)
						ssl_stream_.next_layer().close(); // cancel async_write
				}
			);
		}
		else
		{
			http::async_write(
				tcp_stream_,
				request->req,
				beast::bind_front_handler(&http_client::on_write_request, shared_from_this())
			);

			timer.async_wait_ex(
				request->limited.write_timeout,
				[this](const boost::system::error_code& ec)
				{
					if (ec != boost::asio::error::operation_aborted)
						tcp_stream_.close(); // cancel async_write
				}
			);
		}
	}

	void on_write_request(beast::error_code ec, std::size_t bytes_transferred)
	{
		timer.cancel();

		boost::ignore_unused(bytes_transferred);

		if (ec)
			return request->end_in_failure(ec, "write");

		if (is_https_request)
		{
			if (request->call_back)
				http::async_read_header(
					ssl_stream_,
					buffer,
					request->res_buffer_body,
					beast::bind_front_handler(&http_client::on_read_response_header, shared_from_this())
				);
			else
				http::async_read_header(
					ssl_stream_,
					buffer,
					request->res_string_body,
					beast::bind_front_handler(&http_client::on_read_response_header, shared_from_this())
				);

			timer.async_wait_ex(
				request->limited.read_response_header_timeout,
				[this](const boost::system::error_code& ec)
				{
					if (ec != boost::asio::error::operation_aborted)
						ssl_stream_.next_layer().close(); // cancel async_write
				}
			);
		}
		else
		{
			if (request->call_back)
				http::async_read_header(
					tcp_stream_,
					buffer,
					request->res_buffer_body,
					beast::bind_front_handler(&http_client::on_read_response_header, shared_from_this())
				);
			else
				http::async_read_header(
					tcp_stream_,
					buffer,
					request->res_string_body,
					beast::bind_front_handler(&http_client::on_read_response_header, shared_from_this())
				);

			timer.async_wait_ex(
				request->limited.read_response_header_timeout,
				[this](const boost::system::error_code& ec)
				{
					if (ec != boost::asio::error::operation_aborted)
						tcp_stream_.close(); // cancel async_write
				}
			);
		}

	}

	void on_read_response_header(beast::error_code ec, std::size_t bytes_transferred)
	{
		timer.cancel();

		if (ec)
			return request->end_in_failure(ec, "read response header");

		 //std::cout << "url:"<< request->url_parsed.host<< ", size:" << request->res.get().body().size() << "\n";

		
		//auto header = request->res_empty_body.get()<>;
		//header = request->res_string_body.get();

		// std::cout << "Headers received: " << request->res_empty_body.get() << std::endl;

		if (auto& opt = request->call_back ? request->res_buffer_body.content_length() : request->res_string_body.content_length())
		{
			content_length = opt.value();
		}

		if (request->call_back)
			async_read_response_body_chunk();
		else
			async_read_response_body();
	}


	void async_read_response_body()
	{
		if (is_https_request)
		{
			http::async_read(
				ssl_stream_,
				buffer,
				request->res_string_body,
				beast::bind_front_handler(&http_client::on_read_response_body, shared_from_this())
			);

			timer.async_wait_ex(
				request->limited.read_response_body_timeout,
				[this](const boost::system::error_code& ec)
				{
					if (ec != boost::asio::error::operation_aborted)
						ssl_stream_.next_layer().close(); // cancel async_write
				}
			);
		}
		else
		{
			http::async_read(
				tcp_stream_,
				buffer,
				request->res_string_body,
				beast::bind_front_handler(&http_client::on_read_response_body, shared_from_this())
			);

			timer.async_wait_ex(
				request->limited.read_response_body_timeout,
				[this](const boost::system::error_code& ec)
				{
					if (ec != boost::asio::error::operation_aborted)
						tcp_stream_.close(); // cancel async_write
				}
			);
		}
	}


	void on_read_response_body(beast::error_code ec, std::size_t bytes_transferred)
	{
		timer.cancel();

		boost::ignore_unused(bytes_transferred);

		if (ec)
			return request->end_in_failure(ec, "read response body");

		std::cout << "url:" << request->url.host << ", size:" << request->res_string_body.get().body().size() << "\n";

		return request->end_in_success();
	}




	void async_read_response_body_chunk()
	{
		/*ssl_stream.async_read_some(
			boost::asio::buffer(request->buffer.prepare(1024)),
			beast::bind_front_handler(&http_client::on_read_response_chunk, shared_from_this())
		);
		*/
		
		/*
		http::async_read(
			ssl_stream,
			request->buffer,
			request->res_empty_body,
			beast::bind_front_handler(&http_client::on_read_response_chunk, shared_from_this())
		);
		*/

		auto& body = request->res_buffer_body.get().body();
		body.data = request->chunk_buffer;
		body.size = sizeof(request->chunk_buffer);

		http::async_read_some(
			ssl_stream_,
			buffer,
			request->res_buffer_body,
			beast::bind_front_handler(&http_client::on_read_response_chunk, shared_from_this())
		);
			
		
	}

	void on_read_response_chunk(beast::error_code ec, std::size_t bytes_transferred)
	{
		//timer.cancel();

		if (ec == boost::asio::error::eof)
		{
			return request->end_in_success();
		}

		if (ec)
			return request->end_in_failure(ec, "read response chunk");


		/*
		request->buffer.commit(bytes_transferred);

		std::cout << boost::beast::buffers_to_string(request->buffer.data());

		request->buffer.consume(bytes_transferred);

		content_recv += bytes_transferred;

		if (content_recv==content_length)
			return request->end_in_success();
		*/

		auto& body = request->res_buffer_body.get().body();
		std::string_view body_chunk = std::string_view(request->chunk_buffer, sizeof(request->chunk_buffer)-body.size);
		
		// std::cout << body_chunk;

		content_recv += bytes_transferred;

		//static int i = 0;

		//if (i++ %10000==0)
		std::cout << "recv:" << content_recv << "\n";
		

		if (request->res_buffer_body.is_done())
 			return request->end_in_success();

		async_read_response_body_chunk();
	}
};

struct io_context_work_thread 
{
	std::thread thread;
	asio::io_context& io_ctx;
	boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_guard;
	io_context_work_thread(asio::io_context& io_c)
		: io_ctx(io_c)
		, work_guard(boost::asio::make_work_guard(io_c))
		, thread(&io_context_work_thread::thread_func, this)
	{
	}
	void thread_func()
	{
		printf("run() start\n");
		io_ctx.restart();
		io_ctx.run();
		printf("run() stop\n");
	}
	~io_context_work_thread()
	{
		work_guard.reset();
		io_ctx.stop();
		thread.join();
	}
};


struct http_client2
{
	int i = 0;
};

struct http_manager
{
	//boost::unordered::concurrent_flat_map<std::string, std::shared_ptr<http_client>> clients;

	std::map<std::string, std::shared_ptr<http_client>> clients;

	asio::io_context io_ctx;
	ssl::context ssl_ctx{ ssl::context::tlsv13_client };

	std::shared_ptr<io_context_work_thread> work_thread;

	void start_work_thread() 
	{
		work_thread = std::make_shared<io_context_work_thread>(io_ctx);
	};

	void stop_work_thread()
	{
		work_thread = nullptr;
	}

	void execute(std::shared_ptr<http_request> req)
	{
		auto client = std::make_shared<http_client>(io_ctx, ssl_ctx);
		client->execute(req);
	}

	bool exist_task(const std::string& url)
	{
		auto f = io_ctx.post(
			boost::asio::use_future([this, &url]()->size_t
			{
				return clients.count(url);
			})
		);
		f.wait();
		return f.get();
	}

	bool add_task(const std::string& url)
	{
		auto f = io_ctx.post(
			boost::asio::use_future([this, &url]()->size_t
				{
					if (clients.count(url))
						return false;

					auto request = std::make_shared<http_request>(url, nullptr);
					auto client = std::make_shared<http_client>(io_ctx, ssl_ctx);
					clients[url] = client;
					client->execute(request);

					return true;
				})
		);
		f.wait();
		return f.get();
	}
};

struct http_tools
{
	static bool sync_http_get(const std::string& url, std::string& out, void* callback = nullptr)
	{
		asio::io_context io_ctx;
		ssl::context ssl_ctx{ ssl::context::tlsv13_client };

		auto request = std::make_shared<simple::http_request>(url, callback);
		if (request->ended) // url is invalid
			return false;

		auto client = std::make_shared<http_client>(io_ctx, ssl_ctx);
		client->execute(request);
		io_ctx.run();
		if (callback)
		{
			return request->res_buffer_body.get().result_int() == 200;
		}
		else
		{
			if (request->res_string_body.get().result_int() == 200)
			{
				out = std::move(request->res_string_body.get().body());
				return true;
			}
		}
		return false;
	}

	static std::optional<std::string> sync_http_get(const std::string& url, void* callback = nullptr)
	{
		std::string res;
		if (sync_http_get(url, res, callback))
			return std::optional<std::string>(std::move(res));
		else
			return std::nullopt;
	}
};


} // namespace simple
