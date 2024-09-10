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
#include <boost/format.hpp>

//Due to the use of asynchronous operations, it is necessary to ensure that the object must exist at the time of the callback. 
//Please use smart pointer of the object. 
//
//DO NOT use the object directly !!!

namespace simple{

namespace asio  = boost::asio;
namespace beast = boost::beast;
namespace ssl   = boost::asio::ssl;
namespace http  = boost::beast::http;

template<int N>
bool http_status_match(int status_code)
{
    return (status_code / 100) == N;
};

using is_http_status_1xx = decltype(http_status_match<1>);
using is_http_status_2xx = decltype(http_status_match<2>);
using is_http_status_3xx = decltype(http_status_match<3>);
using is_http_status_4xx = decltype(http_status_match<4>);
using is_http_status_5xx = decltype(http_status_match<5>);

inline void fail(beast::error_code ec, char const* what)
{
    std::cerr << what << ": " << ec.message() << "\n";
}

inline bool fail(char const* message, char const* what)
{
    std::cerr << what << ": " << message << "\n";
    return false;
}

enum class HttpErrorCode {
    INVALID_URL	= 0x1001,
    INVALID_REQUEST,

    TIMEOUT_RESOLVE = 0X2001,
    TIMEOUT_CONNECT,
    TIMEOUT_SSL_HANDSHAKE,	// https only
    TIMEOUT_WRITE_REQUEST,
    TIMEOUT_READ_RESPONSE_HEADER,
    TIMEOUT_READ_RESPONSE_BODY,
    TIMEOUT_READ_RESPONSE_SLICE	
};

using error_code = boost::system::error_code;

class HttpErrorCategory : public boost::system::error_category
{
public:
    const char* name() const noexcept override
    {
        return "simple::HttpErrorCategory";
    }

    std::string message(int ev) const override
    {
        switch (static_cast<HttpErrorCode>(ev))
        {
        case HttpErrorCode::INVALID_URL:
            return "url is invalid";
        case HttpErrorCode::INVALID_REQUEST:
            return "request is invalid";
        case HttpErrorCode::TIMEOUT_RESOLVE:
            return "resolve timeout";
        case HttpErrorCode::TIMEOUT_CONNECT:
            return "connect timeout";
        case HttpErrorCode::TIMEOUT_SSL_HANDSHAKE:
            return "ssl handshake timeout";
        case HttpErrorCode::TIMEOUT_WRITE_REQUEST:
            return "write request timeout";
        case HttpErrorCode::TIMEOUT_READ_RESPONSE_HEADER:
            return "read response header";
        case HttpErrorCode::TIMEOUT_READ_RESPONSE_BODY:
            return "read response body";
        case HttpErrorCode::TIMEOUT_READ_RESPONSE_SLICE:
            return "read response slice";
        default:
            return "unknown error ";
        }
    }

    static const error_code make_error_code(HttpErrorCode e)
    {
        static HttpErrorCategory _;
        return error_code(static_cast<int>(e), _);
    }
};


const error_code INVALID_URL                    = HttpErrorCategory::make_error_code(HttpErrorCode::INVALID_URL);
const error_code INVALID_REQUEST                = HttpErrorCategory::make_error_code(HttpErrorCode::INVALID_REQUEST);
const error_code TIMEOUT_RESOLVE                = HttpErrorCategory::make_error_code(HttpErrorCode::TIMEOUT_RESOLVE);
const error_code TIMEOUT_CONNECT                = HttpErrorCategory::make_error_code(HttpErrorCode::TIMEOUT_CONNECT);
const error_code TIMEOUT_SSL_HANDSHAKE          = HttpErrorCategory::make_error_code(HttpErrorCode::TIMEOUT_SSL_HANDSHAKE);
const error_code TIMEOUT_WRITE_REQUEST          = HttpErrorCategory::make_error_code(HttpErrorCode::TIMEOUT_WRITE_REQUEST);
const error_code TIMEOUT_READ_RESPONSE_HEADER   = HttpErrorCategory::make_error_code(HttpErrorCode::TIMEOUT_READ_RESPONSE_HEADER);
const error_code TIMEOUT_READ_RESPONSE_BODY     = HttpErrorCategory::make_error_code(HttpErrorCode::TIMEOUT_READ_RESPONSE_BODY);
const error_code TIMEOUT_READ_RESPONSE_SLICE    = HttpErrorCategory::make_error_code(HttpErrorCode::TIMEOUT_READ_RESPONSE_SLICE);


struct Url
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
    bool is_valid()
    {
        return (
            scheme.length() &&
            host.length() &&
            port.length() &&
            path.length()
        );
    }
    std::string path_to_resource() const
    {
        if (query.length())
            return path + "?" + query;
        else
            return path;
    }

    std::string endpoint() const
    {
        return scheme + "://" + host + ":" + port;
    }

    std::string to_url() const
    {
        return endpoint() + path_to_resource();
    }

    std::string to_uri() const
    {
        if (fragment.length())
            return endpoint() + path_to_resource() + "#" + fragment;
        else
            return endpoint() + path_to_resource();
    }

    bool set(const std::string& url_str)
    {
        return parse(url_str, *this);
    }

    static bool parse(const std::string& url_str, Url& out)
    {
        std::regex url_regex(R"(([^:]+):\/\/([^\/:]+)(?::(\d+))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?)");
        std::smatch url_match;

        if (std::regex_match(url_str, url_match, url_regex))
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
                else
                {
                    assert(0);
                }
            }

            out.path = url_match[4].str();
            if (out.path.length() == 0)
                out.path = "/";

            out.query = url_match[5].str();
            out.fragment = url_match[6].str();

            return true;
        }
        else 
        {
            return false;
        }
    }
};

struct HttpContext;
struct HttpManager;

struct HttpCallback
{
    using OnRecvHeader  = std::function<void(const HttpContext* ctx, int status_code)>;
    using OnRecvSlice   = std::function<void(const HttpContext* ctx, uint64_t offset, std::string_view& slice)>;
    using OnComplete    = std::function<void(const HttpContext* ctx, int status_code, const std::string& body)>;
    using OnDataNeeded  = std::function<bool(std::string& buf)>;
    using OnTimer       = std::function<void(const boost::system::error_code& ec)>;
};

struct MultipartBodyItem
{
    std::string name;   // NOT empty !
    std::string value;  // if empty, try get value by callback function: on_data_needed

    std::string content_type;       // if empty, ignore
    std::string file_name;          // if empty, ignore

    HttpCallback::OnDataNeeded on_data_needed = nullptr;

    MultipartBodyItem(std::string_view name, std::string_view value)
    {
        this->name = name;
        this->value = value;
    }

    MultipartBodyItem(std::string_view name, std::string_view file_name, std::string_view file_content)
    {
        this->name = name;
        this->value = file_content;
        this->file_name = file_name;
    }

    MultipartBodyItem(std::string_view name, std::string_view file_name, const HttpCallback::OnDataNeeded& data_needed_handler)
    {
        this->name = name;
        this->file_name = file_name;
        this->on_data_needed = data_needed_handler;
    }
};

struct HttpContext : public std::enable_shared_from_this<HttpContext>
{
    struct
    {
        HttpCallback::OnRecvHeader  on_recv_header;
        HttpCallback::OnRecvSlice   on_recv_slice;
        HttpCallback::OnComplete    on_complete;

        void recv_header(const HttpContext* ctx, int status_code)
        {
            if (on_recv_header)
                on_recv_header(ctx, status_code);
        }
        void recv_slice(const HttpContext* ctx, uint64_t offset, std::string_view& slice)
        {
            if (on_recv_slice)
                on_recv_slice(ctx, offset, slice);
        }
        void http_complete(const HttpContext* ctx, int status_code, const std::string& body)
        {
            if (on_complete)
                on_complete(ctx, status_code, body);
        }

    } callback;

    struct
    {
        uint16_t    resolve_timeout = 5 * 1000;
        uint16_t    connect_timeout = 5 * 1000;
        uint16_t    handshake_timeout = 5 * 1000;
        uint16_t    write_timeout = 5 * 1000;
        uint16_t    read_response_header_timeout = 5 * 1000;
        uint16_t    read_response_body_timeout = 10 * 1000;
        uint16_t    read_response_chunk_timeout = 2 * 1000;

        uint64_t    string_body_limit = 32 * 1024 * 1024;

        int         version = 11; // http 1.1
    } config;

    struct
    {
        volatile bool       completed = false;
        beast::error_code   last_error;
    } status;

    bool is_completed()
    {
        return status.completed;
    }
    
    struct
    {
        Url             url;
        std::string     method;
        int             range_from;
        
        http::request<http::string_body> body;

        std::vector<MultipartBodyItem> post;

        void set_range(int from)
        {
            range_from = from;
            std::string range_str = (boost::format("bytes=%d-") % from).str();
            body.set(http::field::range, range_str);
        }

        std::string url_string() const
        {
            return url.to_url();
        }
    } request;

    struct
    {
        uint64_t content_length = 0;
        uint64_t slice_recv_bytes = 0;

        std::shared_ptr<http::response_parser<http::string_body>> string_body;

        std::shared_ptr<http::response_parser<http::buffer_body>> buffer_body; // it use buffer_memory
        char buffer_memory[1024 * 10];

        std::string_view slice_view()
        {
            auto& body = buffer_body->get().body();
            return std::string_view(buffer_memory, sizeof(buffer_memory) - body.size);
        }

        void prepare_slice_memory()
        {
            auto& body = buffer_body->get().body();
            body.data = buffer_memory;
            body.size = sizeof(buffer_memory);
        }

    } response;

    HttpContext() = delete;

    HttpContext(
        const std::string& url,
        const HttpCallback::OnRecvHeader& recv_header_handler,
        const HttpCallback::OnRecvSlice& recv_slice_handler,
        const HttpCallback::OnComplete& http_finish_handler
    )
    {
        callback.on_recv_header = recv_header_handler;
        callback.on_recv_slice = recv_slice_handler;
        callback.on_complete = http_finish_handler;

        init(url);
    }

    static std::shared_ptr<HttpContext> create(
        const std::string& url,
        const HttpCallback::OnRecvHeader& recv_header_handler = nullptr,
        const HttpCallback::OnRecvSlice& recv_slice_handler = nullptr,
        const HttpCallback::OnComplete& http_finish_handler = nullptr)
    {
        return std::make_shared<HttpContext>(
            url,
            recv_header_handler,
            recv_slice_handler,
            http_finish_handler
        );
    }
    ~HttpContext()
    {
        return;
    }
    bool re_init()
    {
        return init("", nullptr);
    }
    bool re_init(const std::string& url)
    {
        return init("", &url);
    }
    bool init(const std::string& url)
    {
        return init("GET", &url);
    }
    bool init(std::string_view method, const std::string* url) // url == nullptr, means reuse old url
    {
        status.completed = false;
        status.last_error.clear();

        response.string_body = std::make_shared<http::response_parser<http::string_body>>();
        response.buffer_body = std::make_shared<http::response_parser<http::buffer_body>>();

        response.content_length = 0;
        response.slice_recv_bytes = 0;
        response.string_body->body_limit(config.string_body_limit);
        response.buffer_body->body_limit(std::numeric_limits<std::uint64_t>::max());

        if (url)
        {
            if (!request.url.set(*url))
            {
                finish_in_failure(INVALID_URL, "parse url");
                return false;
            }
        }
        else
        {
            // use old request_url
        }

        if (!method.empty())
        {
            request.method = method;
        }

        request.body = http::request<http::string_body>();
        {
            auto& req_body = request.body;
            req_body.method_string(request.method);
            req_body.version(config.version);
            req_body.target(request.url.path_to_resource());
            req_body.set(http::field::host, request.url.host);
            req_body.set(http::field::connection, "keep-alive");
        }

        return true;
    }
    
    bool is_slice_mode() const
    {
        return callback.on_recv_slice != nullptr;
    }

    bool finished_in_success() const
    {
        return (status.last_error.failed() == false);
    }

    int response_status_code()
    {
        if (is_slice_mode())
            return response.buffer_body->get().result_int();
        else
            return response.string_body->get().result_int();
    }

    std::string& response_body()
    {
        static std::string __empty;
        if (is_slice_mode())
            return __empty;
        else
            return response.string_body->get().body();
    }

    std::string response_location()
    {
        if (is_slice_mode())
        {
            auto& rsp = response.buffer_body->get();
            auto location = rsp.find(beast::http::field::location);
            if (location != rsp.end())
                return location->value();
        }
        else
        {
            auto& rsp = response.string_body->get();
            auto location = rsp.find(beast::http::field::location);
            if (location != rsp.end())
                return location->value();
        }
        return "";
    }

    void on_recv_slice()
    {
        auto slice = response.slice_view();
        auto offset = response.slice_recv_bytes;
        response.slice_recv_bytes += slice.size();
        callback.recv_slice(this, request.range_from + offset, slice);
    }

    void on_http_complete()
    {
        status.completed = true;
        if (auto& last_error = status.last_error)
            callback.http_complete(this, last_error.value(), response_body());
        else
            callback.http_complete(this, response_status_code(), response_body());
    }

    void on_recv_header()
    {
        auto opt = is_slice_mode() ? response.buffer_body->content_length() : response.string_body->content_length();
        if (opt)
        {
            response.content_length = opt.value();
        }

        callback.recv_header(this, response_status_code());
    }

    void finish_in_failure(const beast::error_code& ec, const std::string& info)
    {
        status.last_error = ec;
        on_http_complete();
        return fail(ec, info.c_str());
    }

    void finish_in_success()
    {
        on_http_complete();
    }

};

struct SteadyTimer : public boost::asio::steady_timer
{
    SteadyTimer(asio::io_context& ioc_ctx)
        : boost::asio::steady_timer(ioc_ctx)
    {
    }
    template <
        BOOST_ASIO_COMPLETION_TOKEN_FOR(void(boost::system::error_code))
        WaitToken = asio::default_completion_token_t<executor_type>>
    void expires_after(int64_t timeout_ms, WaitToken&& token = asio::default_completion_token_t<executor_type>())
    {
        boost::asio::steady_timer::expires_after(std::chrono::milliseconds(timeout_ms));
        async_wait(token);
    }
};

struct HttpConnection : public std::enable_shared_from_this<HttpConnection>
{
    beast::ssl_stream<beast::tcp_stream> ssl_stream_;
    beast::tcp_stream tcp_stream_;
    SteadyTimer timer;

    asio::ip::tcp::resolver resolver;

    beast::flat_buffer buffer;

    std::shared_ptr<HttpContext> http_ctx; 
    
    bool is_https_request = false;
    bool is_reusable = false;
    
    HttpConnection(asio::io_context& ioc_ctx, ssl::context& ssl_ctx)
        : ssl_stream_(ioc_ctx, ssl_ctx)
        , tcp_stream_(ioc_ctx)
        , resolver(ioc_ctx)
        , timer(ioc_ctx)
    {
    }
    ~HttpConnection()
    {
        return;
    }

    inline beast::tcp_stream& get_tcp_stream()
    {
        return is_https_request ? beast::get_lowest_layer(ssl_stream_) : tcp_stream_;
    }

    void finish_in_failure(const beast::error_code& ec, const std::string& info)
    {
        is_reusable = false;
        return http_ctx->finish_in_failure(ec, info);
    }

    void finish_in_success()
    {
        is_reusable = true;
        return http_ctx->finish_in_success();
    }
    

    void execute(std::shared_ptr<HttpContext> ctx)
    {
        http_ctx = ctx;

        if (http_ctx->is_completed())
            return finish_in_failure(INVALID_REQUEST, "http_client::execute");

        if (is_reusable)
        {
            is_reusable = false;
            printf("simple::http find & reuse a exist connection: %s \n", http_ctx->request.url_string());
            on_handshake(beast::error_code());
            return;
        }
        else
        {
            printf("simple::http start a new connection: %s \n", http_ctx->request.url_string());
        }

        is_https_request = http_ctx->request.url.scheme == "https";

        buffer.clear();

        if (is_https_request)
        {
            // Set SNI Hostname (many hosts need this to handshake successfully)
            if (!SSL_set_tlsext_host_name(ssl_stream_.native_handle(), http_ctx->request.url.host.c_str()))
            {
                beast::error_code ec{ static_cast<int>(::ERR_get_error()), asio::error::get_ssl_category() };
                return finish_in_failure(ec, "SSL_set_tlsext_host_name");
            }
        }

        resolver.async_resolve(
            http_ctx->request.url.host,
            http_ctx->request.url.port,
            beast::bind_front_handler(&HttpConnection::on_resolve, shared_from_this())
        );

        
        timer.expires_after( 
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
            return finish_in_failure(ec, "resolve");

        for (auto& it : results)
        {
            std::cout << it.host_name() << ":" << it.service_name() << " => " << it.endpoint().address() << ":" << it.endpoint().port() << std::endl;
        }

        get_tcp_stream().async_connect(
                results,
                beast::bind_front_handler(&HttpConnection::on_connect, shared_from_this())
        );
        
        timer.expires_after(
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
            return finish_in_failure(ec, "connect");

        if (is_https_request)
        {
            // Perform the SSL handshake
            ssl_stream_.async_handshake(
                ssl::stream_base::client,
                beast::bind_front_handler(&HttpConnection::on_handshake, shared_from_this())
            );

            timer.expires_after(
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
            return finish_in_failure(ec, "handshake");

        if (http_ctx->request.method == "POST")
        {
            std::string boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
            std::stringstream body;

            for (auto& it : http_ctx->request.post)
            {
                body << "--" << boundary << "\r\n";

                if (it.file_name.size())
                {
                    body << "Content-Disposition: form-data; name=\"" << it.name << "\"; filename=\"" << it.file_name << "\"\r\n";
                    body << "Content-Type: application/octet-stream\r\n\r\n";
                }
                else 
                    body << "Content-Disposition: form-data; name=\"" << it.name << "\"\r\n\r\n";
                
                if (it.on_data_needed)
                {
                    std::string buf;
                    it.on_data_needed(buf);
                    body << buf << "\r\n";
                }
                else
                { 
                    body << it.value << "\r\n";
                }
            }

            body << "--" << boundary << "--\r\n";

            auto& req_body = http_ctx->request.body;
            {
                req_body.set(http::field::content_type, "multipart/form-data; boundary=" + boundary);
                req_body.body() = body.str();
                req_body.prepare_payload();
            }
        }

        if (is_https_request)
        {
            http::async_write(
                ssl_stream_,
                http_ctx->request.body,
                beast::bind_front_handler(&HttpConnection::on_write_request, shared_from_this())
            );

            timer.expires_after(
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
                http_ctx->request.body,
                beast::bind_front_handler(&HttpConnection::on_write_request, shared_from_this())
            );

            timer.expires_after(
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
            return finish_in_failure(ec, "write");

        if (is_https_request)
        {
            if (http_ctx->is_slice_mode())
                http::async_read_header(
                    ssl_stream_,
                    buffer,
                    *http_ctx->response.buffer_body,
                    beast::bind_front_handler(&HttpConnection::on_read_response_header, shared_from_this())
                );
            else
                http::async_read_header(
                    ssl_stream_,
                    buffer,
                    *http_ctx->response.string_body,
                    beast::bind_front_handler(&HttpConnection::on_read_response_header, shared_from_this())
                );

            timer.expires_after(
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
                    *http_ctx->response.buffer_body,
                    beast::bind_front_handler(&HttpConnection::on_read_response_header, shared_from_this())
                );
            else
                http::async_read_header(
                    tcp_stream_,
                    buffer,
                    *http_ctx->response.string_body,
                    beast::bind_front_handler(&HttpConnection::on_read_response_header, shared_from_this())
                );

            timer.expires_after(
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
            return finish_in_failure(ec, "read response header");

        // TBD
        http_ctx->on_recv_header();

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
                *http_ctx->response.string_body,
                beast::bind_front_handler(&HttpConnection::on_read_response_body, shared_from_this())
            );

            timer.expires_after(
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
                *http_ctx->response.string_body,
                beast::bind_front_handler(&HttpConnection::on_read_response_body, shared_from_this())
            );

            timer.expires_after(
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
            return finish_in_failure(ec, "read response body");

        std::cout << "url:" << http_ctx->request.url.host << ", size:" << http_ctx->response.string_body->get().body().size() << "\n";

        return finish_in_success();
    }

    void async_read_response_body_slice()
    {

        http_ctx->response.prepare_slice_memory();

        if (is_https_request)
        {
            http::async_read_some(
                ssl_stream_,
                buffer,
                *http_ctx->response.buffer_body,
                beast::bind_front_handler(&HttpConnection::on_read_response_slice, shared_from_this())
            );

            timer.expires_after(
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
                *http_ctx->response.buffer_body,
                beast::bind_front_handler(&HttpConnection::on_read_response_slice, shared_from_this())
            );

            timer.expires_after(
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
            return finish_in_success(); // TODO?
        }

        if (ec)
            return finish_in_failure(ec, "read response slice");

        http_ctx->on_recv_slice();

        if (http_ctx->response.buffer_body->is_done())
            return finish_in_success();

        async_read_response_body_slice();
    }
};

struct IOContextWorker 
{
    asio::io_context& io_ctx;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_guard;
    std::thread thread;
    IOContextWorker(asio::io_context& io_c)
        : io_ctx(io_c)
        , work_guard(boost::asio::make_work_guard(io_c))
        , thread(&IOContextWorker::thread_func, this)
    {
    }
    void thread_func()
    {
        printf("run() start\n");
        io_ctx.restart();
        io_ctx.run();
        printf("run() stop\n");
    }
    ~IOContextWorker()
    {
        work_guard.reset();
        io_ctx.stop();
        thread.join();
    }
};

struct HttpManager
{
    void start_work_thread()
    {
        worker = std::make_shared<IOContextWorker>(io_ctx);
    };

    void stop_work_thread()
    {
        worker = nullptr;
    }

    template<typename WorkHandler>
    auto thread_safe(WorkHandler handler)
    {
        auto f = io_ctx.dispatch(boost::asio::use_future(handler));
        f.wait();
        return f.get();
    }

    void _thread_timer_func(const boost::system::error_code& ec, int64_t timeout_ms, HttpCallback::OnTimer f, std::shared_ptr<SteadyTimer> timer)
    {
        if (ec == asio::error::operation_aborted) // cancel
            return;

        f(ec);

        timer->expires_after(
            timeout_ms,
            [this, timeout_ms, f, timer](const boost::system::error_code& ec)
            {
                _thread_timer_func(ec, timeout_ms, f, timer);
            }
        );
    }

    std::shared_ptr<SteadyTimer> thread_timer(int64_t timeout_ms, HttpCallback::OnTimer f)
    {
        std::shared_ptr<SteadyTimer> timer = std::make_shared<SteadyTimer>(io_ctx);

        timer->expires_after(
            timeout_ms,
            [this, timeout_ms, f, timer](const boost::system::error_code& ec) 
            {
                _thread_timer_func(ec, timeout_ms, f, timer);
            }
        );

        return timer;
    }

    
    std::shared_ptr<HttpContext> create_http_and_execute(
        const std::string& url,
        const HttpCallback::OnRecvHeader& recv_header_handler = nullptr,
        const HttpCallback::OnRecvSlice& recv_slice_handler = nullptr, 
        const HttpCallback::OnComplete& http_finish_handler = nullptr
    )
    {
        auto req = HttpContext::create(url, recv_header_handler, recv_slice_handler, http_finish_handler);
        if (req->is_completed())
            return nullptr;

        this->execute(req);
        return req->shared_from_this();
    }

    void execute(std::shared_ptr<HttpContext> req)
    {
        auto client = thread_safe(
            [&]()->std::shared_ptr<HttpConnection>
            {
                return get_http_client(req->request.url.endpoint());
            }
        );

        auto on_http_finish = req->callback.on_complete;
        req->callback.on_complete = [this,client,on_http_finish](const HttpContext* ctx, int status_code, const std::string& body)
            {
                printf("simple::http finished:%s, status:%d, content:%d \n", ctx->request.url_string(), status_code, ctx->response.content_length);
                this->recycle_http_client(client);
                on_http_finish(ctx, status_code, body);
            };
        client->execute(req);
    }

    std::shared_ptr<HttpConnection> get_http_client(const std::string connection)
    {
        std::shared_ptr<HttpConnection> client;
        auto it = http_client_pool.find(connection);
        if (it == http_client_pool.end())
        {
            client = std::make_shared<HttpConnection>(io_ctx, ssl_ctx);
        }
        else
        {
            client = it->second;
            http_client_pool.erase(it);
        }
        return client;
    }

    void recycle_http_client(std::shared_ptr<HttpConnection> client)
    {
        if (client->is_reusable)
        {
            http_client_pool.insert({ client->http_ctx->request.url.endpoint(), client });
        }
    }

    void stop()
    {
        io_ctx.stop();
    }

protected:
    asio::io_context io_ctx;
    ssl::context ssl_ctx{ ssl::context::tlsv13_client };
    std::shared_ptr<IOContextWorker> worker;
    std::unordered_multimap<std::string, std::shared_ptr<HttpConnection>> http_client_pool;
};

struct Http
{
    struct Sync
    {
        static bool Operate(std::shared_ptr<HttpContext> request, std::string& out, int64_t timeout_ms)
        {
            asio::io_context io_ctx;
            ssl::context ssl_ctx{ ssl::context::tlsv13_client };
            SteadyTimer timer{ io_ctx };

            request->callback.on_complete = [&timer](const HttpContext* ctx, int status_code, const std::string& body) {
                timer.cancel();
                };

            auto client = std::make_shared<HttpConnection>(io_ctx, ssl_ctx);
            client->execute(request);

            timer.expires_after(timeout_ms, [&io_ctx](const boost::system::error_code& ec) {
                io_ctx.stop();
                });

            io_ctx.run();

            if (request->response.string_body->get().result_int() == 200 && request->response.string_body->is_done())
            {
                out = std::move(request->response.string_body->get().body());
                return true;
            }
            return false;
        }

        static bool Get(const std::string& url, std::string& out, int64_t timeout_ms)
        {
            auto request = HttpContext::create(url);
            return Operate(request, out, timeout_ms);
        }

        static bool Post(const std::string& url, const std::vector<MultipartBodyItem>& items, std::string& out, int64_t timeout_ms)
        {
            auto http_ctx = HttpContext::create("");
            http_ctx->init("POST", &url);
            http_ctx->request.post = items;

            return Operate(http_ctx, out, timeout_ms);
        }

        static std::optional<std::string> Get(const std::string& url, int64_t timeout_ms)
        {
            std::string res;
            if (Get(url, res, timeout_ms))
                return std::optional<std::string>(std::move(res));
            else
                return std::nullopt;
        }
    };
};


} // namespace simple
