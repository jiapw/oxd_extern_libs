#pragma once

#include <string>
#include <iostream>
#include <regex>
#include <thread>
#include <chrono>

#include <boost/unordered/concurrent_flat_set.hpp>
#include <boost/algorithm/string.hpp>

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>

//#include <boost/beast/core.hpp>
//#include <boost/beast/http.hpp>
//#include <boost/beast/ssl.hpp>

/*
namespace simple {

	namespace net = boost::asio; // from <boost/asio.hpp>
	namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>

	namespace __details {

		namespace beast = boost::beast; // from <boost/beast.hpp>
		namespace http = beast::http; // from <boost/beast/http.hpp>
		using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>

		// Report a failure
		void
			fail(beast::error_code ec, char const* what)
		{
			std::cerr << what << ": " << ec.message() << "\n";
		}

		
		struct session_limit
		{
			using duration = std::chrono::steady_clock::duration;

			duration resolve_timeout = std::chrono::milliseconds(10*1000);
			duration connect_timeout = std::chrono::milliseconds(10*1000);
		};

		class steady_timer_ex : public boost::asio::steady_timer
		{
		public:
			steady_timer_ex(const executor_type& ex)
				:boost::asio::steady_timer(ex)
			{
			};

			volatile bool finished=false;
		};

		// Performs an HTTP GET and prints the response
		class session : public std::enable_shared_from_this<session> {
			tcp::resolver resolver_;
			steady_timer_ex timer_;
			
			beast::ssl_stream<beast::tcp_stream> stream_;
			beast::flat_buffer buffer_; // (Must persist between reads)
			http::request<http::empty_body> req_;
			http::response<http::string_body> res_;
			session_limit limit_;

		public:
			explicit session(net::any_io_executor ex, ssl::context& ssl_ctx)
				: resolver_(ex)
				, stream_(ex, ssl_ctx)
				, timer_(ex)

			{
			}

			// Start the asynchronous operation
			void run(char const* host,
				char const* port,
				char const* target,
				int version)
			{
				// Set SNI Hostname (many hosts need this to handshake successfully)
				if (!SSL_set_tlsext_host_name(stream_.native_handle(), host)) {
					beast::error_code ec{ static_cast<int>(::ERR_get_error()),
						net::error::get_ssl_category() };
					std::cerr << ec.message() << "\n";
					return;
				}

				// stream_.set_verify_callback(boost::asio::ssl::rfc2818_verification(host));

				// Set up an HTTP GET request message
				req_.version(version);
				req_.method(http::verb::get);
				req_.target(target);
				req_.set(http::field::host, host);
				//req_.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

				// Look up the domain name
				timer_.finished = false;
				resolver_.async_resolve(
					host,
					port,
					beast::bind_front_handler(&session::on_resolve, shared_from_this()));

				// start timer
				timer_.expires_after(limit_.resolve_timeout);
				timer_.async_wait([this](const boost::system::error_code& ec) {
					if (ec != boost::asio::error::operation_aborted) {
						if (timer_.finished)
							return;
						resolver_.cancel(); // Cancel async resolve operation
					}
					timer_.finished = true;
					});
			}

			void on_resolve(beast::error_code ec, tcp::resolver::results_type results)
			{
				timer_.finished = true;

				if (ec)
					return fail(ec, "resolve");


				for (auto& it : results)
				{ 
					 std::cout << it.host_name() << ":"<<it.service_name()<< " => " << it.endpoint().address()<<":"<<it.endpoint().port() << std::endl;
				}


				// Set a timeout on the operation
				beast::get_lowest_layer(stream_).expires_after(limit_.connect_timeout);

				// Make the connection on the IP address we get from a lookup
				beast::get_lowest_layer(stream_).async_connect(
					results,
					beast::bind_front_handler(&session::on_connect, shared_from_this()));
			}

			void on_connect(beast::error_code ec,
				tcp::resolver::results_type::endpoint_type)
			{
				if (ec)
					return fail(ec, "connect");

				// Perform the SSL handshake
				stream_.async_handshake(
					ssl::stream_base::client,
					beast::bind_front_handler(&session::on_handshake, shared_from_this()));
			}

			void on_handshake(beast::error_code ec)
			{
				if (ec)
					return fail(ec, "handshake");

				// Set a timeout on the operation
				beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

				// Send the HTTP request to the remote host
				http::async_write(
					stream_,
					req_,
					beast::bind_front_handler(&session::on_write, shared_from_this()));
			}

			void on_write(beast::error_code ec, std::size_t bytes_transferred)
			{
				boost::ignore_unused(bytes_transferred);

				if (ec)
					return fail(ec, "write");

				// Receive the HTTP response
				http::async_read(
					stream_,
					buffer_,
					res_,
					beast::bind_front_handler(&session::on_read, shared_from_this()));
			}

			void on_read(beast::error_code ec, std::size_t bytes_transferred)
			{
				boost::ignore_unused(bytes_transferred);

				if (ec)
					return fail(ec, "read");

				// Write the message to standard out
				std::cout << res_ << std::endl;

				// Set a timeout on the operation
				beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

				// Gracefully close the stream
				stream_.async_shutdown(
					beast::bind_front_handler(&session::on_shutdown, shared_from_this()));
			}

			void on_shutdown(beast::error_code ec)
			{
				if (ec == net::error::eof) {
					// Rationale:
					// http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
					ec = {};
				}
				if (ec)
					return fail(ec, "shutdown");

				// If we get here then the connection is closed gracefully
			}
		};

	} // namespace __details

	class io_context {
	public:
		io_context() { }
		~io_context() {

		};

	protected:
		boost::asio::io_context io_c;
	};

	class http {
	public:
		enum status_code : int {
			http_ok = 200,

			net_error = -1,
			net_error_dns_query_failed = -2,
		};

		static int get(
			const std::string& host,
			const std::string& port,
			const std::string& target,
			const std::string& version,
			std::string& res_body)
		{
			// The io_context is required for all I/O
			net::io_context io_ctx;

			// The SSL context is required, and holds certificates
			ssl::context ssl_ctx{ ssl::context::tlsv12_client };

			// This holds the root certificate used for verification
			// load_root_certificates(ctx);
			// ssl_ctx.set_default_verify_paths();

			// Verify the remote server's certificate
			// ssl_ctx.set_verify_mode(ssl::verify_peer);

			std::make_shared<__details::session>(net::make_strand(io_ctx), ssl_ctx)
				->run(host.c_str(),
					port.c_str(),
					target.c_str(),
					(version == "1.1" ? 11 : 10));

			io_ctx.run();
			return EXIT_SUCCESS;
		}
		
	};

} // namespace simple

*/


namespace simple{

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace ssl	= boost::asio::ssl;
namespace http	= boost::beast::http;


struct parsed_url
{
	std::string scheme;
	std::string host;
	std::string port;
	std::string path;
	std::string query;
	std::string fragment;
};

bool parse_url(const std::string& url, parsed_url& out) 
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
		std::cerr << "Invalid URL format: " << url << std::endl;
		return false;
	}
}

void fail(beast::error_code ec, char const* what)
{
	std::cerr << what << ": " << ec.message() << "\n";
}

bool fail(char const* message, char const* what)
{
	std::cerr << what << ": " << message << "\n";
	return false;
}


struct http_request: public std::enable_shared_from_this<http_request>
{
	bool finished = false;

	int version = 11; // http 1.1
	
	parsed_url url_parsed;

	http::request<http::empty_body> req;
	http::response<http::string_body> res;

	beast::error_code ec;

	operator std::shared_ptr<http_request>() {
		return shared_from_this();
	}

	http_request(const std::string& url)
	{
		config(url);
	}
	bool config(const std::string& s)
	{
		return config("GET", s);
	}
	bool config(std::string_view method, const std::string& s)
	{
		req.clear();
		res.clear();

		if (!parse_url(s, url_parsed))
			return fail("Invalid URL format", "parse url");

		req.method_string(method);
		req.version(version);
		req.target(url_parsed.path);
		req.set(http::field::host, url_parsed.host);

		return true;
	}
};

struct http_client : public std::enable_shared_from_this<http_client>
{
	beast::ssl_stream<beast::tcp_stream> ssl_stream;
	asio::ip::tcp::resolver resolver;

	std::shared_ptr<http_request> request; 
	
	http_client(asio::io_context& ioc_ctx, ssl::context& ssl_ctx)
		: ssl_stream(ioc_ctx, ssl_ctx)
		, resolver(ioc_ctx)

	{
	}

	void execute(std::shared_ptr<http_request> req)
	{
		request = req;

		// Set SNI Hostname (many hosts need this to handshake successfully)
		if (!SSL_set_tlsext_host_name(ssl_stream.native_handle(), request->url_parsed.host.c_str())) {
			beast::error_code ec{ static_cast<int>(::ERR_get_error()),
				asio::error::get_ssl_category() };
			std::cerr << ec.message() << "\n";
			return;
		}

		resolver.async_resolve(request->url_parsed.host,
			request->url_parsed.port,
			beast::bind_front_handler(&http_client::on_resolve, shared_from_this()));
	}

	void on_resolve(beast::error_code ec, asio::ip::tcp::resolver::results_type results)
	{

		if (ec)
			return fail(ec, "resolve");


		for (auto& it : results)
		{
			std::cout << it.host_name() << ":" << it.service_name() << " => " << it.endpoint().address() << ":" << it.endpoint().port() << std::endl;
		}

		request->finished = true;
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
	boost::unordered::concurrent_flat_set<std::shared_ptr<http_client>> clients;

	asio::io_context io_ctx;
	ssl::context ssl_ctx{ ssl::context::tlsv12_client };

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
};




} // namespace simple
