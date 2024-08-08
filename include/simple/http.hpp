#pragma once

#include <string>
#include <iostream>
#include <regex>
#include <thread>
#include <chrono>

#include <future>
#include <unordered_map>

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

struct http_context;

using on_http_recv_header_func = std::function<void(const http_context* ctx, int status_code)>;
using on_http_recv_slice_func = std::function<void(const http_context* ctx, uint64_t offset, std::string_view& slice)>;
using on_http_finish_func = std::function<void(const http_context* ctx, int status_code, const std::string& body)>;

using get_body_func = std::function<void(std::string& buf)>;

struct multipart_body_item
{

	std::string name;	// NOT empty !
	std::string value;
	std::string content_length = 0;
	std::string content_type = "";	// skip if empty

	std::string file_name;

	get_body_func get_body = nullptr;

	multipart_body_item(std::string_view name, std::string_view value)
	{
		this->name = name;
		this->value = value;
	}

	multipart_body_item(std::string_view name, std::string_view file_name, std::string_view file_content)
	{
		this->name = name;
		this->value = file_content;
		this->file_name = file_name;
	}

	multipart_body_item(std::string_view name, std::string_view file_name, get_body_func get_body)
	{
		this->name = name;
		this->file_name = file_name;
		this->get_body = get_body;
	}
};


struct http_context // : public std::enable_shared_from_this<http_request>
{

protected:
	struct
	{
		on_http_finish_func			on_http_finish;
		on_http_recv_slice_func		on_recv_slice;
		on_http_recv_header_func	on_recv_header;
	} callback;
public:
	struct
	{
		uint16_t	resolve_timeout = 5 * 1000;
		uint16_t	connect_timeout = 5 * 1000;
		uint16_t	handshake_timeout = 5 * 1000;
		uint16_t	write_timeout = 5 * 1000;
		uint16_t	read_response_header_timeout = 5 * 1000;
		uint16_t	read_response_body_timeout = 10 * 1000;
		uint16_t	read_response_chunk_timeout = 2 * 1000;

		uint64_t	string_body_limit = 32 * 1024 * 1024; // complete

		int			version = 11; // http 1.1
	} config;

	volatile bool finished = false;

	beast::error_code error_code;
	
	std::vector<multipart_body_item> post_data;
		
	http_url request_url;

	http::request<http::string_body> request;

	struct
	{
		uint64_t content_length = 0;
		uint64_t slice_recv_bytes = 0;

		http::response_parser<http::string_body> string_body;

		http::response_parser<http::buffer_body> buffer_body; // it use buffer_memory
		char buffer_memory[1024 * 10];

		std::string_view slice_view()
		{
			auto& body = buffer_body.get().body();
			return std::string_view(buffer_memory, sizeof(buffer_memory) - body.size);
		}

		void prepare_slice_memory()
		{
			auto& body = buffer_body.get().body();
			body.data = buffer_memory;
			body.size = sizeof(buffer_memory);
		}

	} response;

	http_context(
        const std::string& url,
        const on_http_recv_header_func& recv_header_handler = nullptr,
        const on_http_recv_slice_func& recv_slice_handler = nullptr,
		const on_http_finish_func& http_finish_handler = nullptr
    )
	{
		callback.on_recv_header = recv_header_handler;
		callback.on_recv_slice = recv_slice_handler;
		callback.on_http_finish = http_finish_handler;

		init(url);
	}
	~http_context()
	{
		return;
	}
	bool init(const std::string& url)
	{
		return init("GET", url);
	}
	bool init(std::string_view method, const std::string& url)
	{
		response.content_length = 0;
		response.slice_recv_bytes = 0;
		response.string_body.body_limit(config.string_body_limit);
		response.buffer_body.body_limit(std::numeric_limits<std::uint64_t>::max());

		finished = false;
		request.clear();
		error_code.clear();

		if (!request_url.parse(url))
		{
			finish_in_failure(http_error_category::ec_invalid_url(), "parse url");
			return false;
		}

		request.method_string(method);
		request.version(config.version);
		request.target(request_url.target());
		request.set(http::field::host, request_url.host);

		return true;
	}

    bool is_slice_mode() const
    {
        return callback.on_recv_slice != nullptr;
    }

	/*
    bool is_complete_mode() const
    {
        return callback.on_recv_slice == nullptr;
    }*/

	int response_status_code()
	{
		if (is_slice_mode())
			return response.buffer_body.get().result_int();
		else
			return response.string_body.get().result_int();
	}

	const std::string& response_body()
	{
		static std::string __empty;
		if (is_slice_mode())
			return __empty;
		else
			return response.string_body.get().body();
	}

	void callback_on_recv_slice(uint64_t offset, std::string_view& slice)
	{
		if (callback.on_recv_slice ==nullptr)
			return;

		callback.on_recv_slice(this, offset, slice);
	}

	void on_recv_slice()
	{
		auto slice = response.slice_view();

		auto offset = response.slice_recv_bytes;
		response.slice_recv_bytes += slice.size();
		callback_on_recv_slice(offset, slice);
	}

	void call_on_http_finish()
	{
		if (callback.on_http_finish == nullptr)
			return;
		
		callback.on_http_finish(this, response_status_code(), response_body());
	}

	void callback_on_recv_header()
	{
		auto opt = is_slice_mode() ? response.buffer_body.content_length() : response.string_body.content_length();
		if (opt)
		{
			response.content_length = opt.value();
		}

		if (callback.on_recv_header==nullptr)
			return;

		callback.on_recv_header(this, response_status_code());
	}

	void finish_in_failure(const beast::error_code ec, const std::string& info)
	{
		call_on_http_finish();

		finished = true;
		error_code = ec;
		return fail(ec, info.c_str());
	}

	void finish_in_success()
	{
		call_on_http_finish();

		finished = true;
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

	std::shared_ptr<http_context> http_ctx; 
	bool is_https_request = false;
	
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

	void execute(std::shared_ptr<http_context> ctx)
	{
		http_ctx = ctx;

		if (http_ctx->finished)
			return http_ctx->finish_in_failure(http_error_category::ec_invalid_request(), "http_client::execute");

		is_https_request = http_ctx->request_url.scheme == "https";

		buffer.clear();

		if (is_https_request)
		{
			// Set SNI Hostname (many hosts need this to handshake successfully)
			if (!SSL_set_tlsext_host_name(ssl_stream_.native_handle(), http_ctx->request_url.host.c_str()))
			{
				beast::error_code ec{ static_cast<int>(::ERR_get_error()), asio::error::get_ssl_category() };
				return http_ctx->finish_in_failure(ec, "SSL_set_tlsext_host_name");
			}
		}

		resolver.async_resolve(
			http_ctx->request_url.host,
			http_ctx->request_url.port,
			beast::bind_front_handler(&http_client::on_resolve, shared_from_this())
		);

		
		timer.async_wait_ex( 
			http_ctx->config.resolve_timeout,
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
			return http_ctx->finish_in_failure(ec, "resolve");

		for (auto& it : results)
		{
			std::cout << it.host_name() << ":" << it.service_name() << " => " << it.endpoint().address() << ":" << it.endpoint().port() << std::endl;
		}

		get_tcp_stream().async_connect(
				results,
				beast::bind_front_handler(&http_client::on_connect, shared_from_this())
		);
		
		timer.async_wait_ex(
			http_ctx->config.connect_timeout,
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
			return http_ctx->finish_in_failure(ec, "connect");

		if (is_https_request)
		{
			// Perform the SSL handshake
			ssl_stream_.async_handshake(
				ssl::stream_base::client,
				beast::bind_front_handler(&http_client::on_handshake, shared_from_this())
			);

			timer.async_wait_ex(
				http_ctx->config.handshake_timeout,
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
			return http_ctx->finish_in_failure(ec, "handshake");

		if (is_https_request)
		{
			http::async_write(
				ssl_stream_,
				http_ctx->request,
				beast::bind_front_handler(&http_client::on_write_request, shared_from_this())
			);

			timer.async_wait_ex(
				http_ctx->config.write_timeout,
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
				http_ctx->request,
				beast::bind_front_handler(&http_client::on_write_request, shared_from_this())
			);

			timer.async_wait_ex(
				http_ctx->config.write_timeout,
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
			return http_ctx->finish_in_failure(ec, "write");

		if (is_https_request)
		{
			if (http_ctx->is_slice_mode())
				http::async_read_header(
					ssl_stream_,
					buffer,
					http_ctx->response.buffer_body,
					beast::bind_front_handler(&http_client::on_read_response_header, shared_from_this())
				);
			else
				http::async_read_header(
					ssl_stream_,
					buffer,
					http_ctx->response.string_body,
					beast::bind_front_handler(&http_client::on_read_response_header, shared_from_this())
				);

			timer.async_wait_ex(
				http_ctx->config.read_response_header_timeout,
				[this](const boost::system::error_code& ec)
				{
					if (ec != boost::asio::error::operation_aborted)
						ssl_stream_.next_layer().close(); // cancel async_write
				}
			);
		}
		else
		{
			if (http_ctx->is_slice_mode())
				http::async_read_header(
					tcp_stream_,
					buffer,
					http_ctx->response.buffer_body,
					beast::bind_front_handler(&http_client::on_read_response_header, shared_from_this())
				);
			else
				http::async_read_header(
					tcp_stream_,
					buffer,
					http_ctx->response.string_body,
					beast::bind_front_handler(&http_client::on_read_response_header, shared_from_this())
				);

			timer.async_wait_ex(
				http_ctx->config.read_response_header_timeout,
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
			return http_ctx->finish_in_failure(ec, "read response header");

		// TBD
		http_ctx->callback_on_recv_header();

		if (http_ctx->is_slice_mode())
			async_read_response_body_slice();
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
				http_ctx->response.string_body,
				beast::bind_front_handler(&http_client::on_read_response_body, shared_from_this())
			);

			timer.async_wait_ex(
				http_ctx->config.read_response_body_timeout,
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
				http_ctx->response.string_body,
				beast::bind_front_handler(&http_client::on_read_response_body, shared_from_this())
			);

			timer.async_wait_ex(
				http_ctx->config.read_response_body_timeout,
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
			return http_ctx->finish_in_failure(ec, "read response body");

		std::cout << "url:" << http_ctx->request_url.host << ", size:" << http_ctx->response.string_body.get().body().size() << "\n";

		return http_ctx->finish_in_success();
	}

	void async_read_response_body_slice()
	{

		http_ctx->response.prepare_slice_memory();

		if (is_https_request)
		{
			http::async_read_some(
				ssl_stream_,
				buffer,
				http_ctx->response.buffer_body,
				beast::bind_front_handler(&http_client::on_read_response_slice, shared_from_this())
			);

			timer.async_wait_ex(
				http_ctx->config.read_response_chunk_timeout,
				[this](const boost::system::error_code& ec)
				{
					if (ec != boost::asio::error::operation_aborted)
						ssl_stream_.next_layer().close(); // cancel async_read_some
				}
			);
		}
		else
		{
			http::async_read_some(
				tcp_stream_,
				buffer,
				http_ctx->response.buffer_body,
				beast::bind_front_handler(&http_client::on_read_response_slice, shared_from_this())
			);

			timer.async_wait_ex(
				http_ctx->config.read_response_chunk_timeout,
				[this](const boost::system::error_code& ec)
				{
					if (ec != boost::asio::error::operation_aborted)
						tcp_stream_.close(); // cancel async_read_some
				}
			);
		}
	}

	void on_read_response_slice(beast::error_code ec, std::size_t bytes_transferred)
	{
		timer.cancel();

		if (ec == boost::asio::error::eof)
		{
			return http_ctx->finish_in_success();
		}

		if (ec)
			return http_ctx->finish_in_failure(ec, "read response slice");

		http_ctx->on_recv_slice();

		if (http_ctx->response.buffer_body.is_done())
 			return http_ctx->finish_in_success();

		async_read_response_body_slice();
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

struct http_manager
{
	void start_work_thread()
	{
		work_thread = std::make_shared<io_context_work_thread>(io_ctx);
	};

	void stop_work_thread()
	{
		work_thread = nullptr;
	}

	template<typename WorkHandler>
	auto post_work_and_wait_result(WorkHandler handler)
	{
		auto f = io_ctx.post(boost::asio::use_future(handler));
		f.wait();
		return f.get();
	}

	bool exist_task(const std::string& url)
	{
		return post_work_and_wait_result([this, &url]()->bool // because post_work_and_wait_result(), we can capture parameters by reference
			{
				return clients.count(url)>0;
			});
	}

	bool add_task(const std::string& url, 
		const on_http_recv_header_func& recv_header_handler = nullptr,
		const on_http_recv_slice_func& recv_slice_handler = nullptr, 
		const on_http_finish_func& http_finish_handler = nullptr
	)
	{
		return post_work_and_wait_result([this, &url, &recv_header_handler, &recv_slice_handler, &http_finish_handler]()->bool // because post_work_and_wait_result(), we can capture parameters by reference
			{
				if (clients.count(url))
					return false;

				auto request = std::make_shared<http_context>(url, recv_header_handler, recv_slice_handler, http_finish_handler);
				auto client = std::make_shared<http_client>(io_ctx, ssl_ctx);
				clients[url] = client;
				this->execute(request);

				return true;
			});
	}

	void execute(std::shared_ptr<http_context> req)
	{
		auto client = std::make_shared<http_client>(io_ctx, ssl_ctx);
		client->execute(req);
	}
	
	std::shared_ptr<http_client> find_client(const std::string& url)
	{
		return clients[url];
	}


protected:
	std::unordered_map<std::string, std::shared_ptr<http_client>> clients;
	asio::io_context io_ctx;
	ssl::context ssl_ctx{ ssl::context::tlsv13_client };
	std::shared_ptr<io_context_work_thread> work_thread;
};

struct http_tools
{
	static bool sync_http_op(std::shared_ptr<http_context> request, std::string& out)
	{
		asio::io_context io_ctx;
		ssl::context ssl_ctx{ ssl::context::tlsv13_client };

		auto client = std::make_shared<http_client>(io_ctx, ssl_ctx);
		client->execute(request);
		io_ctx.run();

		if (request->response.string_body.get().result_int() == 200)
		{
			out = std::move(request->response.string_body.get().body());
			return true;
		}
		return false;
	}

	static bool sync_http_get(const std::string& url, std::string& out)
	{
		auto request = std::make_shared<simple::http_context>(url);
		return sync_http_op(request, out);
	}

	static bool sync_http_post(const std::string& url, const std::vector<multipart_body_item>& items, std::string& out)
	{
		auto request = std::make_shared<simple::http_context>("");
		request->init("POST", url);
		request->post_data = items;

		return sync_http_op(request, out);
	}

	static std::optional<std::string> sync_http_get(const std::string& url)
	{
		std::string res;
		if (sync_http_get(url, res))
			return std::optional<std::string>(std::move(res));
		else
			return std::nullopt;
	}
};


} // namespace simple
