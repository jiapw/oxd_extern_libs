#pragma once

#include <string>
#include <iostream>
#include <regex>
#include <thread>
#include <chrono>

#include <future>
#include <unordered_map>

#define BOOST_ASIO_ENABLE_CANCELIO
#define BOOST_ASIO_NO_DEPRECATED
#define BOOST_EXCEPTION_DISABLE

#include <boost/algorithm/string.hpp>

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>

#include "fmt.hpp"
#include "log.hpp"
#include "time.hpp"


namespace simple
{

#define HTTP_ERROR_LIST(XX) \
    XX(INVALID_URL,                     0x1001, "Invalid URL") \
    XX(INVALID_REQUEST,                 0x1002, "Invalid request") \
    XX(INVALID_STATUS,                  0x1003, "Invalid status") \
    XX(TIMEOUT_RESOLVE,                 0x2001, "Timeout during DNS resolution") \
    XX(TIMEOUT_CONNECT,                 0x2002, "Timeout during TCP connect") \
    XX(TIMEOUT_SSL_HANDSHAKE,           0x2003, "Timeout during SSL handshake") \
    XX(TIMEOUT_WRITE_REQUEST,           0x2004, "Timeout writing request") \
    XX(TIMEOUT_READ_RESPONSE_HEADER,    0x2005, "Timeout reading response header") \
    XX(TIMEOUT_READ_RESPONSE_BODY,      0x2006, "Timeout reading response body") \
    XX(TIMEOUT_READ_RESPONSE_SLICE,     0x2007, "Timeout reading response slice") \
    XX(FAILED_RESOLVE,                  0x3001, "Failed to resolve host") \
    XX(FAILED_CONNECT,                  0x3002, "Failed to connect") \
    XX(FAILED_SSL_HANDSHAKE,            0x3003, "Failed SSL handshake") \
    XX(FAILED_READ,                     0x3004, "Failed to read from socket") \
    XX(FAILED_WRITE,                    0x3005, "Failed to write to socket") \
    XX(FAILED_BY_UPPER_LAYER,           0x3006, "Request canceled by upper layer") \
    XX(FAILED_REDIRECT_COUNT,           0x3007, "Too many redirects") \
    XX(FAILED_REDIRECT_LOCATION,        0x3008, "Invalid redirect location") \
    XX(BLOCKED_BY_CONFIG,               0x4001, "Blocked by configuration") \
    XX(BLOCKED_BY_FAILURE_CACHE,        0x4002, "Blocked due to failure cache")

enum class HttpError
{
#define NAME_VALUE(name, value, str) name = value,
    HTTP_ERROR_LIST(NAME_VALUE)
#undef NAME_VALUE
};

inline const char* HttpErrorString(HttpError code)
{
    switch (code) {
#define CASE_NAME_RETURN_STRING(name, value, str) case HttpError::name: return str;
        HTTP_ERROR_LIST(CASE_NAME_RETURN_STRING)
#undef CASE_NAME_RETURN_STRING
    default: return "Unknown HTTP error";
    }
}

class HttpErrorCategory : public boost::system::error_category
{
public:
    const char* name() const noexcept override 
    {
        return "simple::HttpErrorCategory";
    }

    std::string message(int ev) const override 
    {
        return HttpErrorString(static_cast<HttpError>(ev));
    }

    inline static const boost::system::error_category& http_error_category() 
    {
        static HttpErrorCategory instance;
        return instance;
    }

    inline static boost::system::error_code make_error_code(HttpError e)
    {
        return { static_cast<int>(e), http_error_category() };
    }
};

inline boost::system::error_code make_error_code(HttpError e) 
{
    return HttpErrorCategory::make_error_code(e);
}

} // namespace simple

namespace boost::system
{
    template <>
    struct is_error_code_enum<simple::HttpError> : std::true_type {};
}

namespace simple
{
    using error_code = boost::system::error_code;

    // define SUCCESS to represent no error
    const error_code SUCCESS = error_code();

    // declare all HttpError
#define DECALRE_CONST(name, value, str) const error_code name = HttpError::name;
    HTTP_ERROR_LIST(DECALRE_CONST)
#undef DECALRE_CONST

} // namespace simple

namespace simple
{

// define a class fully compatible with boost::beast::http::string_body, prepare for specialization of boost::beast::http::serializer 
struct string_body : public boost::beast::http::string_body {};

} // namespace simple

namespace boost::beast::http {

template<
    bool isRequest,
    class Fields>
class serializer<isRequest, simple::string_body, Fields> : public serializer<isRequest, string_body, Fields>
{
public:
    using Base = serializer<isRequest, string_body, Fields>;

    size_t header_size;
    size_t payload_size;
    size_t total;
    size_t finished;

    explicit serializer(message<isRequest, string_body, Fields>& msg)
        : Base(msg)
    {
        calc_size(msg);

        finished = 0;
        total = header_size + payload_size;
    }

    void calc_size(message<isRequest, http::string_body, Fields>& msg)
    {
        payload_size = msg.payload_size().value_or(0);

        header_size = 0;
        {
            // 1. "GET /index.html HTTP/1.1\r\n"
            header_size += msg.method_string().size() + 1;  // GET + space
            header_size += msg.target().size() + 1;         // path + space
            header_size += 8 + 2; // "HTTP/1.1" + "\r\n"

            // 2. all fields
            for (const auto& field : msg) {
                header_size += field.name_string().size() + 2;  // "Header: "
                header_size += field.value().size() + 2;        // "Value\r\n"
            }

            // 3. empty line "\r\n"
            header_size += 2;
        }
    }

    void consume(std::size_t n)
    {
        Base::consume(n);
        finished += n;
    }

    size_t progress()
    {
        return finished*1000/total;
    }
};

}



//Due to the use of asynchronous operations, it is necessary to ensure that the object must exist at the time of the callback. 
//Please use smart pointer of the object. 
//
//DO NOT use the object directly !!!


template<>
struct fmt::formatter<boost::asio::ip::basic_resolver_iterator<boost::asio::ip::tcp>::value_type> : fmt::formatter<std::string>
{
    auto format(const boost::asio::ip::basic_resolver_iterator<boost::asio::ip::tcp>::value_type& A, format_context& ctx) const -> decltype(ctx.out())
    {
        const auto& ep = A.endpoint();
        //return format_to(ctx.out(), "{}->{}", A.host_name(), ep.address().to_string());
        return format_to(ctx.out(), "{}", ep.address().to_string());
    }
};

namespace simple{

namespace asio  = boost::asio;
namespace beast = boost::beast;
namespace ssl   = boost::asio::ssl;
namespace http  = boost::beast::http;

LOG_DEFINE(SMP_HTTP);

template<int N>
bool http_status_match(int status_code)
{
    return (status_code / 100) == N;
};

inline auto is_http_status_1xx = http_status_match<1>;
inline auto is_http_status_2xx = http_status_match<2>;
inline auto is_http_status_3xx = http_status_match<3>;
inline auto is_http_status_4xx = http_status_match<4>;
inline auto is_http_status_5xx = http_status_match<5>;

inline void fail(beast::error_code ec, char const* what)
{
    SMP_HTTP::Warn("failed: {}, {}", what, ec.message());
}

inline bool fail(char const* message, char const* what)
{
    SMP_HTTP::Warn("failed: {}, {}", what, message);
    return false;
}

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

    bool is_same_endpoint(Url& b) const
    {
        return scheme == b.scheme && host == b.host && port == b.port;
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

struct HttpResultCache
{
protected:
    struct Result
    {
        int failed_count;
        int64_t last_failed_tms;
        int64_t unfreeze_tms;
    };

    std::unordered_map<std::string, Result> results;

    HttpResultCache()
    {
    }
    void report_result(const std::string& url, int status_code)
    {
        auto now = simple::ms::now();
        auto it = results.find(url);

        if (is_http_status_2xx(status_code) || is_http_status_3xx(status_code))
        {
            if (it == results.end())
                return;

            results.erase(it);
            return;
        }

        if (it == results.end())
        {
            results.insert({
                url,
                {
                    1,
                    now,
                    now + 1000 * 1
                }
                });
        }
        else
        {
            auto& result = it->second;
            result.failed_count++;
            result.last_failed_tms = now;
            result.unfreeze_tms = now + calc_recommended_interval(result.failed_count);
        }
    }
    bool is_freezed(const std::string& url)
    {
        auto it = results.find(url);
        if (it == results.end())
            return false;
        auto& result = it->second;
        return (simple::ms::now() < result.unfreeze_tms);
    }
    int64_t get_unfreeze_time(const std::string& url)
    {
        auto it = results.find(url);
        if (it == results.end())
            return 0;
        return it->second.unfreeze_tms;
    }
    int64_t calc_recommended_interval(int64_t fc)
    {
        static int64_t pending_table[] = { 0, 8*1000, 16*1000, 32 * 1000 };

        if (fc < std::size(pending_table))
            return pending_table[fc];
        else
            return 64 * 1000 * fc;
    }
    int64_t get_recommended_interval(const std::string& url)
    {
        auto it = results.find(url);
        if (it == results.end())
            return 0;
        return calc_recommended_interval(it->second.failed_count);
    }
public:
    static HttpResultCache& Singletone()
    {
        static HttpResultCache _;
        return _;
    }
    static void ReportResult(const std::string& url, int status_code)
    {
        static HttpResultCache& cache = Singletone();
        cache.report_result(url, status_code);
    }
    static bool IsFreezed(const std::string& url)
    {
        static HttpResultCache& cache = Singletone();
        return cache.is_freezed(url);
    }
    static int64_t GetUnfreezeTime(const std::string& url)
    {
        static HttpResultCache& cache = Singletone();
        return cache.get_unfreeze_time(url);
    }
    static int64_t GetRecommendedInterval(const std::string& url)
    {
        static HttpResultCache& cache = Singletone();
        return cache.get_unfreeze_time(url);
    }
    static int64_t CalcRecommendedInterval(int64_t failed_count)
    {
        static HttpResultCache& cache = Singletone();
        return cache.calc_recommended_interval(failed_count);
    }
};

struct HttpContext;
struct HttpManager;

struct HttpCallback
{
    using OnRecvHeader  = std::function<bool(HttpContext* ctx, int http_status_code)>; // if you want to end the request, return false
    using OnRecvSlice   = std::function<bool(HttpContext* ctx, uint64_t offset, std::string_view& slice)>; // if you want to end the request, return false
    using OnComplete    = std::function<void(HttpContext* ctx, const error_code& sys_error_code, int http_status_code, const std::string& body)>;
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
    struct Callback
    {
        HttpCallback::OnRecvHeader  on_recv_header;
        HttpCallback::OnRecvSlice   on_recv_slice;
        HttpCallback::OnComplete    on_complete;

        HttpContext* ctx = nullptr;

        bool recv_header(int http_status_code)
        {
            if (on_recv_header)
                return on_recv_header(ctx, http_status_code);
            else
                return true;
        }
        bool recv_slice(uint64_t offset, std::string_view& slice)
        {
            if (on_recv_slice)
                return on_recv_slice(ctx, offset, slice);
            else
                return false;
        }
        void http_complete(const error_code& sys_error_code, int http_status_code, const std::string& body)
        {
            if (on_complete)
                on_complete(ctx, sys_error_code, http_status_code, body);
        }
    } callback;

    struct
    {
        int         version = 11;                   // use http 1.1 by default

        uint16_t    resolve_timeout = 5 * 1000;     // timeouts are in milliseconds
        uint16_t    connect_timeout = 5 * 1000;
        uint16_t    handshake_timeout = 5 * 1000;
        uint32_t    write_timeout = 5 * 1000;
        uint16_t    read_response_header_timeout = 5 * 1000;
        uint16_t    read_response_body_timeout = 10 * 1000;
        uint16_t    read_response_chunk_timeout = 2 * 1000;

        uint64_t    string_body_limit = 32 * 1024 * 1024;   // 32M

        int         redirect_limit = 1;             // the number of http redirects allowed
        int         log_slice_interval_ms = 100;    // less than 0: never;     equal to 0: always;
        
        
    } config;

    struct
    {
        volatile bool       completed = false;
        beast::error_code   sys_error_code;
        int                 http_status_code = 0;
        int                 response_version = 10;
        int                 redirect_count = 0;
        int64_t             last_log_timestamp = 0;
    } status;

    bool is_completed()
    {
        return status.completed;
    }

    struct
    {
        Url             url;
        std::string     method;
        int             range_from = 0;
        
        http::request<http::string_body> http_request;
        std::shared_ptr<boost::beast::http::serializer<true, simple::string_body>> http_request_serializer;

        std::vector<MultipartBodyItem> post;

        void set_range(int from)
        {
            range_from = from;
            std::string range_str = fmt::format("bytes={}-", from);
            http_request.set(http::field::range, range_str);
        }

        std::string url_string() const
        {
            return url.to_url();
        }

        size_t progress()
        {
            if (!http_request_serializer)
                return 0;
            return http_request_serializer->progress();
        }
        size_t total()
        {
            if (!http_request_serializer)
                return 0;
            return http_request_serializer->total;
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
        callback.ctx = this;
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
        status.sys_error_code.clear();

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
                SMP_HTTP::Warn(
                    "failed in parse url: \"{}\", caused by: {}",
                    *url,
                    INVALID_URL.message()
                );
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

        request.http_request = http::request<http::string_body>();
        {
            auto& req = request.http_request;
            req.method_string(request.method);
            req.version(config.version);
            req.target(request.url.path_to_resource());
            req.set(http::field::host, request.url.host);
            req.set(http::field::connection, "keep-alive");
        }

        return true;
    }
    
    bool is_slice_mode() const
    {
        return callback.on_recv_slice != nullptr;
    }

    bool finished_in_success() const
    {
        return (!status.sys_error_code.failed() && is_http_status_2xx(status.http_status_code));
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

    bool on_recv_slice()
    {
        if (auto now = simple::ms::now(); config.log_slice_interval_ms == 0 || (status.last_log_timestamp + config.log_slice_interval_ms) < now)
        {
            SMP_HTTP::Trace(
                "HttpContext recv slice: {} {}, ({}|{}):{}",
                request.method,
                request.url.to_url(),
                response.content_length,
                response.slice_recv_bytes,
                response.slice_view().size()
            );
            status.last_log_timestamp = now;
        }

        auto slice = response.slice_view();
        auto offset = response.slice_recv_bytes;
        response.slice_recv_bytes += slice.size();
        return callback.recv_slice(request.range_from + offset, slice);
    }

    void on_http_complete()
    {
        status.completed = true;
        if (auto& last_error = status.sys_error_code)
            callback.http_complete(last_error, 0, "");
        else
            callback.http_complete(SUCCESS, response_status_code(), response_body());
    }

    template<class T>
    void process_http_header(T body)
    {
        status.http_status_code = body->get().result_int();
        status.response_version = body->get().version();
        if (auto opt = body->content_length(); opt)
            response.content_length = opt.value();
    }

    bool on_recv_header()
    {
        if (is_slice_mode())
            process_http_header(response.buffer_body);
        else
            process_http_header(response.string_body);

        HttpResultCache::ReportResult(request.url_string(), status.http_status_code);

        return callback.recv_header(status.http_status_code);
    }

    void finish_in_failure(const beast::error_code& ec, const std::string& info)
    {
        status.sys_error_code = ec;
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
        async_wait(std::forward<WaitToken>(token));
    }
    void cancel()
    {
        boost::asio::steady_timer::cancel();
    }
};

struct HttpConnection : public std::enable_shared_from_this<HttpConnection>
{
    typedef beast::ssl_stream<beast::tcp_stream> https_stream;
    typedef beast::tcp_stream http_stream;

    std::shared_ptr<https_stream> ssl_stream_ptr;
    std::shared_ptr<http_stream> tcp_stream_ptr;


    SteadyTimer timer;

    asio::ip::tcp::resolver resolver;

    beast::flat_buffer buffer;

    std::shared_ptr<HttpContext> http_ctx; 
    
    bool is_https_request = false;
    bool is_reusable = false;
    simple::ms::timestamp finished_tm;

    asio::io_context& ioc_ctx;
    ssl::context& ssl_ctx;
    
    HttpConnection(asio::io_context& ioc_ctx, ssl::context& ssl_ctx)
        : ioc_ctx(ioc_ctx)
        , ssl_ctx(ssl_ctx)
        , resolver(ioc_ctx)
        , timer(ioc_ctx)
    {
    }
    ~HttpConnection()
    {
        return;
    }

    std::string to_string(int level = 0)
    {
        if (level == 1)
            return fmt::format("HttpConnection(addr:{}, is_reusable:{})", (void*)this, is_reusable);
        
        return fmt::format("HttpConnection({})", (void*)this);
    }

    inline beast::tcp_stream& get_tcp_stream()
    {
        return is_https_request ? ssl_stream_ptr->next_layer() : (*tcp_stream_ptr);
    }

    void finish_in_failure(const beast::error_code& ec, const std::string& info)
    {
        finished_tm.reset_now();
        is_reusable = false;
        return http_ctx->finish_in_failure(ec, info);
    }

    void finish_in_success()
    {
        finished_tm.reset_now();
        is_reusable = true;
        return http_ctx->finish_in_success();
    }
    

    void execute(std::shared_ptr<HttpContext> ctx)
    {
        http_ctx = ctx;

        if (http_ctx->is_completed())
            return finish_in_failure(INVALID_REQUEST, "HttpConnection::execute");

        if (ctx->request.method == "GET") // only block get
        {
            if (HttpResultCache::IsFreezed(ctx->request.url_string()))
                return finish_in_failure(BLOCKED_BY_FAILURE_CACHE, "HttpConnection::execute");
        }

        SMP_HTTP::Trace(
            "{} execute: {} {}",
            this->to_string(),
            ctx->request.method,
            ctx->request.url_string()
        );

        if (is_reusable)
        {
            is_reusable = false;
            on_handshake(beast::error_code());
            return;
        }

        is_https_request = http_ctx->request.url.scheme == "https";

        buffer.clear();

        if (is_https_request)
        {
            ssl_stream_ptr = std::make_shared<https_stream>(ioc_ctx, ssl_ctx);
            // Set SNI Hostname (many hosts need this to handshake successfully)
            if (!SSL_set_tlsext_host_name(ssl_stream_ptr->native_handle(), http_ctx->request.url.host.c_str()))
            {
                beast::error_code ec{ static_cast<int>(::ERR_get_error()), asio::error::get_ssl_category() };
                return finish_in_failure(ec, "SSL_set_tlsext_host_name");
            }
        }
        else
        {
            tcp_stream_ptr = std::make_shared<http_stream>(ioc_ctx);
        }

        timer.expires_after(
            http_ctx->config.resolve_timeout,
            [self = shared_from_this()](const boost::system::error_code& ec)
            {
                if (ec != boost::asio::error::operation_aborted)
                    self->resolver.cancel(); // cancel async_resolve
            }
        );

        resolver.async_resolve(
            http_ctx->request.url.host,
            http_ctx->request.url.port,
            beast::bind_front_handler(&HttpConnection::on_resolve, shared_from_this())
        );
    }

    void on_resolve(beast::error_code ec, asio::ip::tcp::resolver::results_type results)
    {
        timer.cancel();

        if (ec)
        {
            SMP_HTTP::Warn(
                "{} failed in resolve: {}, caused by: {}",
                this->to_string(),
                http_ctx->request.url.host,
                ec.message()
            );

            if (ec == asio::error::operation_aborted)
                return finish_in_failure(TIMEOUT_RESOLVE, "resolve");
            else
                return finish_in_failure(ec, "resolve");
        }

        SMP_HTTP::Trace(
            "{} resolve {}, result: [{}]", 
            this->to_string(),
            results.begin()->host_name(),
            fmt::join(results, ", ")
        );

        timer.expires_after(
            http_ctx->config.connect_timeout,
            [self = shared_from_this()](const boost::system::error_code& ec)
            {
                if (ec != boost::asio::error::operation_aborted)
                {
                    self->get_tcp_stream().close(); // cancel async_connect
                }

            }
        );

        get_tcp_stream().async_connect(
                results,
                beast::bind_front_handler(&HttpConnection::on_connect, shared_from_this())
        );
    }

    void on_connect(beast::error_code ec, asio::ip::tcp::resolver::results_type::endpoint_type)
    {
        timer.cancel();

        if (ec)
        {
            SMP_HTTP::Warn(
                "{} failed in connect: {}:{}, caused by: {}",
                this->to_string(),
                http_ctx->request.url.host,
                http_ctx->request.url.port,
                ec.message()
            );
            return finish_in_failure(ec, "connect");
        }

        SMP_HTTP::Trace(
            "{} connected: {}:{}",
            this->to_string(),
            http_ctx->request.url.host,
            http_ctx->request.url.port
        );

        if (is_https_request)
        {
            timer.expires_after(
                http_ctx->config.handshake_timeout,
                [self = shared_from_this()](const boost::system::error_code& ec)
                {
                    if (ec != boost::asio::error::operation_aborted)
                        self->get_tcp_stream().close(); // cancel async_connect
                }
            );

            // Perform the SSL handshake
            ssl_stream_ptr->async_handshake(
                ssl::stream_base::client,
                beast::bind_front_handler(&HttpConnection::on_handshake, shared_from_this())
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
        {
            SMP_HTTP::Warn(
                "{} failed in handshake: {}, caused by: {}",
                this->to_string(),
                http_ctx->request.url.host,
                ec.message()
            );
            HttpResultCache::ReportResult(http_ctx->request.url_string(), ec.value());
            return finish_in_failure(ec, "handshake");
        }

        if (http_ctx->request.method == "POST")
        {
            std::string boundary = "----WebKitFormBoundary"+std::to_string(simple::nanoseconds::now());
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

            auto& req = http_ctx->request.http_request;
            {
                req.set(http::field::content_type, "multipart/form-data; boundary=" + boundary);
                req.body() = body.str();
                req.prepare_payload();
            }
            
            uint32_t timeout_at_128kbps = (uint32_t)(req.body().size() / (128 * 1024 / 8)) * 1000;
            if (timeout_at_128kbps > http_ctx->config.write_timeout)
                http_ctx->config.write_timeout = timeout_at_128kbps;

            SMP_HTTP::Trace(
                "{} post: {} bytes, timeout: {} ms",
                this->to_string(),
                req.body().size(),
                http_ctx->config.write_timeout
            );
        }

        SMP_HTTP::Trace(
            "{} request: {}, {}",
            this->to_string(),
            http_ctx->request.method,
            http_ctx->request.url_string()
        );

        http_ctx->request.http_request_serializer = std::make_shared<boost::beast::http::serializer<true, simple::string_body>>(http_ctx->request.http_request);

        if (is_https_request)
        {
            timer.expires_after(
                http_ctx->config.write_timeout,
                [self = shared_from_this()](const boost::system::error_code& ec)
                {
                    if (ec != boost::asio::error::operation_aborted)
                        self->ssl_stream_ptr->next_layer().close(); // cancel async_write
                }
            );

            http::async_write(
                *ssl_stream_ptr,
                *http_ctx->request.http_request_serializer,
                beast::bind_front_handler(&HttpConnection::on_write_request, shared_from_this())
            );

        }
        else
        {
            timer.expires_after(
                http_ctx->config.write_timeout,
                [self = shared_from_this()](const boost::system::error_code& ec)
                {
                    if (ec != boost::asio::error::operation_aborted)
                        self->tcp_stream_ptr->close(); // cancel async_write
                }
            );

            http::async_write(
                *tcp_stream_ptr,
                *http_ctx->request.http_request_serializer,
                beast::bind_front_handler(&HttpConnection::on_write_request, shared_from_this())
            );

        }
    }

    void on_write_request(beast::error_code ec, std::size_t bytes_transferred)
    {
        timer.cancel();

        boost::ignore_unused(bytes_transferred);

        if (ec)
        {
            SMP_HTTP::Warn(
                "{} failed in write request: {}, caused by: {}",
                this->to_string(),
                http_ctx->request.url_string(),
                ec.message()
            );
            return finish_in_failure(ec, "write request");
        }

        SMP_HTTP::Trace(
            "{} send request: {} bytes, finished: {}%",
            this->to_string(),
            http_ctx->request.total(),
            http_ctx->request.progress() /10
        );

        if (is_https_request)
        {
            timer.expires_after(
                http_ctx->config.read_response_header_timeout,
                [self = shared_from_this()](const boost::system::error_code& ec)
                {
                    if (ec != boost::asio::error::operation_aborted)
                        self->ssl_stream_ptr->next_layer().close(); // cancel async_write
                }
            );

            if (http_ctx->is_slice_mode())
                http::async_read_header(
                    *ssl_stream_ptr,
                    buffer,
                    *http_ctx->response.buffer_body,
                    beast::bind_front_handler(&HttpConnection::on_read_response_header, shared_from_this())
                );
            else
                http::async_read_header(
                    *ssl_stream_ptr,
                    buffer,
                    *http_ctx->response.string_body,
                    beast::bind_front_handler(&HttpConnection::on_read_response_header, shared_from_this())
                );

        }
        else
        {
            timer.expires_after(
                http_ctx->config.read_response_header_timeout,
                [self = shared_from_this()](const boost::system::error_code& ec)
                {
                    if (ec != boost::asio::error::operation_aborted)
                        self->tcp_stream_ptr->close(); // cancel async_write
                }
            );

            if (http_ctx->is_slice_mode())
                http::async_read_header(
                    *tcp_stream_ptr,
                    buffer,
                    *http_ctx->response.buffer_body,
                    beast::bind_front_handler(&HttpConnection::on_read_response_header, shared_from_this())
                );
            else
                http::async_read_header(
                    *tcp_stream_ptr,
                    buffer,
                    *http_ctx->response.string_body,
                    beast::bind_front_handler(&HttpConnection::on_read_response_header, shared_from_this())
                );

        }

    }

    void on_read_response_header(beast::error_code ec, std::size_t bytes_transferred)
    {
        timer.cancel();

        if (ec)
        {
            SMP_HTTP::Warn(
                "{} failed in read response header: {}, caused by: {}",
                this->to_string(),
                http_ctx->request.url_string(),
                ec.message()
            );
            return finish_in_failure(ec, "read response header");
        }

        if (!http_ctx->on_recv_header())
        {
            return finish_in_failure(FAILED_BY_UPPER_LAYER, "read response header");
        }

        if (http_ctx->is_slice_mode())
            async_read_response_body_slice();
        else
            async_read_response_body();
    }


    void async_read_response_body()
    {
        if (is_https_request)
        {
            timer.expires_after(
                http_ctx->config.read_response_body_timeout,
                [self = shared_from_this()](const boost::system::error_code& ec)
                {
                    if (ec != boost::asio::error::operation_aborted)
                        self->ssl_stream_ptr->next_layer().close(); // cancel async_write
                }
            );

            http::async_read(
                *ssl_stream_ptr,
                buffer,
                *http_ctx->response.string_body,
                beast::bind_front_handler(&HttpConnection::on_read_response_body, shared_from_this())
            );

        }
        else
        {
            timer.expires_after(
                http_ctx->config.read_response_body_timeout,
                [self = shared_from_this()](const boost::system::error_code& ec)
                {
                    if (ec != boost::asio::error::operation_aborted)
                        self->tcp_stream_ptr->close(); // cancel async_write
                }
            );

            http::async_read(
                *tcp_stream_ptr,
                buffer,
                *http_ctx->response.string_body,
                beast::bind_front_handler(&HttpConnection::on_read_response_body, shared_from_this())
            );

        }
    }


    void on_read_response_body(beast::error_code ec, std::size_t bytes_transferred)
    {
        timer.cancel();

        boost::ignore_unused(bytes_transferred);

        if (ec)
            return finish_in_failure(ec, "read response body");

        SMP_HTTP::Trace("{} completed request: {} {} => [{}] {} Bytes",
            this->to_string(),
            http_ctx->request.method,
            http_ctx->request.url.to_url(),
            http_ctx->status.http_status_code,
            http_ctx->response.string_body->get().body().size()
        );
        
        handle_response_finish();
    }

    void handle_response_finish()
    {
        auto& status = http_ctx->status;

        if (status.http_status_code == 0)
            return finish_in_failure(INVALID_STATUS, "handle_response_finish without http_status_code");

        // 2xx
        if (is_http_status_2xx(status.http_status_code))
            return finish_in_success();

        // 3xx, redirect?
        if (is_http_status_3xx(status.http_status_code))
        {
            if (status.redirect_count > http_ctx->config.redirect_limit)
                return finish_in_failure(FAILED_REDIRECT_COUNT, "redirect too many times");

            status.redirect_count++;

            std::string location = http_ctx->response_location();
            Url url_b;
            if (!url_b.set(location))
                return finish_in_failure(FAILED_REDIRECT_LOCATION, "redirect location invalid");

            SMP_HTTP::Trace("{} redirect: {} => {}",
                this->to_string(),
                http_ctx->request.url.to_url(),
                location
            );


            // http 1.1 && same endpoint
            if (status.response_version == 11
                && http_ctx->request.url.is_same_endpoint(url_b))
            {
                // reuse connection, send new HTTP request
                http_ctx->re_init(location);
                on_handshake(error_code());
            }
            else
            {
                // close connection, restart
                http_ctx->re_init(location);
                execute(http_ctx);
            }

            return;
        }

        return finish_in_success();
    }

    void async_read_response_body_slice()
    {
        if (http_ctx->response.buffer_body->is_done())
            return handle_response_finish();

        http_ctx->response.prepare_slice_memory();

        if (is_https_request)
        {
            timer.expires_after(
                http_ctx->config.read_response_chunk_timeout,
                [self = shared_from_this()](const boost::system::error_code& ec)
                {
                    if (ec != boost::asio::error::operation_aborted)
                        self->ssl_stream_ptr->next_layer().close(); // cancel async_read_some
                }
            );

            http::async_read_some(
                *ssl_stream_ptr,
                buffer,
                *http_ctx->response.buffer_body,
                beast::bind_front_handler(&HttpConnection::on_read_response_slice, shared_from_this())
            );

        }
        else
        {
            timer.expires_after(
                http_ctx->config.read_response_chunk_timeout,
                [self = shared_from_this()](const boost::system::error_code& ec)
                {
                    if (ec != boost::asio::error::operation_aborted)
                        self->tcp_stream_ptr->close(); // cancel async_read_some
                }
            );

            http::async_read_some(
                *tcp_stream_ptr,
                buffer,
                *http_ctx->response.buffer_body,
                beast::bind_front_handler(&HttpConnection::on_read_response_slice, shared_from_this())
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
        {
            SMP_HTTP::Trace(
                "{} read response slice failed: {}, {}",
                this->to_string(),
                http_ctx->request.url.host,
                ec.message()
            );
            return finish_in_failure(ec, "read response slice");
        }

        if (!http_ctx->on_recv_slice())
        {
            return finish_in_failure(FAILED_BY_UPPER_LAYER, "read response slice");
        }

        if (http_ctx->response.buffer_body->is_done())
            handle_response_finish();
        else
            async_read_response_body_slice();
    }
};

struct IOContextWorker : public std::enable_shared_from_this<IOContextWorker>
{
    asio::io_context& io_ctx;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_guard;
    std::thread thread;
    enum class st
    {
        init = 0,
        start,
        stop
    };
    volatile st thread_state = st::init;
    IOContextWorker(asio::io_context& io_c)
        : io_ctx(io_c)
        , work_guard(boost::asio::make_work_guard(io_c))
        , thread(&IOContextWorker::thread_func, this)
    {
    }
    bool is_running()
    {
        return thread_state == st::start;
    }
    void thread_func()
    {
        SMP_HTTP::Debug("IOContextWorker start");
        thread_state = st::start;

        io_ctx.restart();
        io_ctx.run();

        thread_state = st::stop;
        SMP_HTTP::Debug("IOContextWorker stop");
    }
    void stop()
    {
        if (!is_running())
            return;

        if (std::this_thread::get_id() == thread.get_id())
        {
            std::thread new_thread(
                [self=shared_from_this()]() {
                    self->work_guard.reset();
                    self->io_ctx.stop();
                    self->thread.join();
                });
            new_thread.detach();
        }
        else
        {
            work_guard.reset();
            io_ctx.stop();
            thread.join();
        }
    }
    ~IOContextWorker()
    {
        stop();
    }
    static std::shared_ptr<IOContextWorker> Create(asio::io_context& io_c)
    {
        return std::make_shared<IOContextWorker>(io_c);
    }
};


#define CHECK_WORK_THREAD \
if (!in_work_thread()) \
{ \
    SMP_HTTP::Critical("current is NOT managed working thread!"); \
}

struct HttpManager : public std::enable_shared_from_this<HttpManager>
{
    HttpManager()
    {
        /*
        ssl_ctx.set_options(
            ssl::context::default_workarounds |
            ssl::context::no_sslv2 |
            CHECK_WORK_THREADssl::context::no_sslv3 |
            ssl::context::no_tlsv1 |
            ssl::context::no_tlsv1_1
        );
        */
    }

    void start_work_thread()
    {
        worker = std::make_shared<IOContextWorker>(io_ctx);
    };

    void stop_work_thread()
    {
        if (!worker)
        {
            SMP_HTTP::Critical("stop_work_thread, but the worker is empty!");
            return;
        }
        worker->stop();
        worker = nullptr;
    }

    bool in_work_thread()
    {
        assert(worker);
        assert(worker->is_running());
        return (std::this_thread::get_id() == worker->thread.get_id());
    }

    bool is_working()
    {
        return worker!=nullptr;
    }

    template<typename WorkHandler>
    auto thread_safe(WorkHandler&& handler)
    {
        auto f = asio::dispatch(io_ctx, boost::asio::use_future(std::forward<WorkHandler>(handler)));
        f.wait();
        return f.get();
    }

    template<typename WorkHandler>
    auto thread_safe_async(WorkHandler&& handler)
    {
        asio::post(io_ctx, std::forward<WorkHandler>(handler));
    }

    void _thread_timer_func(const boost::system::error_code& ec, int64_t timeout_ms, HttpCallback::OnTimer f, std::shared_ptr<SteadyTimer> timer)
    {
        // CHECK_WORK_THREAD;

        if (ec == asio::error::operation_aborted) // cancel
            return;

        if (worker && worker->is_running()) // The first execution of a newly created timer may be scheduled to execute earlier than subsequent code in the parent thread.
        {
            f(ec);
        }

        timer->expires_after(
            timeout_ms,
            [self = shared_from_this(), timeout_ms, f, timer](const boost::system::error_code& ec)
            {
                self->_thread_timer_func(ec, timeout_ms, f, timer);
            }
        );
    }

    std::shared_ptr<SteadyTimer> create_thread_timer(int64_t timeout_ms, HttpCallback::OnTimer f)
    {
        std::shared_ptr<SteadyTimer> timer = std::make_shared<SteadyTimer>(io_ctx);

        timer->expires_after(
            timeout_ms,
            [self = shared_from_this(), timeout_ms, f, timer](const boost::system::error_code& ec)
            {
                self->_thread_timer_func(ec, timeout_ms, f, timer);
            }
        );

        return timer;
    }

    
    std::pair<std::shared_ptr<HttpConnection>, std::shared_ptr<HttpContext>>
    create_http_and_execute(
        const std::string& url,
        const HttpCallback::OnRecvHeader& recv_header_handler = nullptr,
        const HttpCallback::OnRecvSlice& recv_slice_handler = nullptr, 
        const HttpCallback::OnComplete& http_finish_handler = nullptr
    )
    {
        auto http_ctx = HttpContext::create(url, recv_header_handler, recv_slice_handler, http_finish_handler);
        if (http_ctx->is_completed())
            return std::pair{nullptr, nullptr};

        auto http_conn = this->execute(http_ctx);
        return std::pair{ http_conn->shared_from_this(), http_ctx->shared_from_this() };
    }

    std::shared_ptr<HttpConnection> execute(std::shared_ptr<HttpContext> http_ctx)
    {
        if (!is_working())
        {
            SMP_HTTP::Critical("HttpManager::execute without working thread!");
            return nullptr;
        }

        auto http_conn = thread_safe(
            [&]()->std::shared_ptr<HttpConnection>
            {
                return get_http_connection(http_ctx->request.url.endpoint());
            }
        );

        auto origin_on_complete = http_ctx->callback.on_complete;
        http_ctx->callback.on_complete = [this, http_conn, origin_on_complete](HttpContext* ctx, const error_code& sys_error_code, int http_status_code, const std::string& body)
            {
                SMP_HTTP::Debug("HttpManager => ({}) Finished:{}, error:{}, http:{}, content:{}",
                    http_conn->to_string(),
                    ctx->request.url_string(),
                    sys_error_code.to_string(),
                    http_status_code, 
                    ctx->response.content_length
                );
                this->recycle_http_connection(http_conn);
                ctx->callback.on_complete = origin_on_complete;
                if (ctx->callback.on_complete)
                    ctx->callback.on_complete(ctx, sys_error_code, http_status_code, body);
            };
        http_conn->execute(http_ctx);
        return http_conn;
    }

    std::shared_ptr<HttpConnection> get_http_connection(const std::string connection)
    {
        CHECK_WORK_THREAD;

        std::shared_ptr<HttpConnection> client;
        auto it = http_connection_pool.find(connection);
        bool from_pool = false;
        if (it == http_connection_pool.end())
        {
            client = std::make_shared<HttpConnection>(io_ctx, ssl_ctx);
        }
        else
        {
            from_pool = true;
            client = it->second;
            http_connection_pool.erase(it);

            if (client->finished_tm.elapsed() > 1000 * 60 )
            {
                SMP_HTTP::Debug("find a expired http connection in the pool, drop it & create new one");
                client = std::make_shared<HttpConnection>(io_ctx, ssl_ctx);
            }
        }
        SMP_HTTP::Debug("get_http_client, {}, from pool:{}, pool size:{}", client->to_string(), from_pool, http_connection_pool.size());
        return client;
    }

    void recycle_http_connection(std::shared_ptr<HttpConnection> http_conn)
    {
        CHECK_WORK_THREAD;

        if (http_conn->is_reusable)
        {
            http_connection_pool.insert({ http_conn->http_ctx->request.url.endpoint(), http_conn });
            SMP_HTTP::Debug("recycle_http_client, {}, pool size:{}", http_conn->to_string(), http_connection_pool.size());
        }
    }

    void stop()
    {
        if (worker)
            worker->stop();
    }

protected:
    asio::io_context io_ctx;
    ssl::context ssl_ctx{ ssl::context::tls_client };
    std::shared_ptr<IOContextWorker> worker;
    std::unordered_multimap<std::string, std::shared_ptr<HttpConnection>> http_connection_pool;
};

struct Http
{
    struct Sync
    {
        static bool Operate(std::shared_ptr<HttpContext> request, std::string& out, int64_t timeout_ms)
        {
            asio::io_context io_ctx;
            ssl::context ssl_ctx{ ssl::context::tls_client };
            SteadyTimer timer{ io_ctx };

            request->callback.on_complete = [&timer](const HttpContext* ctx, const error_code& sys_error_code, int http_status_code, const std::string& body) {
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
