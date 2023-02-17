#pragma once

#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")

#include "sws/server_https.hpp"

namespace websvc {

/**
 * Implementation of XxxServer for Simple-Web-Server
 *
 * Simple-Web-Server
 *   homepage: https://gitlab.com/eidheim/Simple-Web-Server
 *   documentation: https://eidheim.gitlab.io/Simple-Web-Server/index.html
 */
class SwsRequest : public HttpRequest {
public:
    using server_impl_type = SimpleWeb::Server<SimpleWeb::HTTPS>;
    using request_impl_type = server_impl_type::Request;

public:
    Result Init(const std::string_view RawRequest) override
    {
        return Result::SS_OK;
    }

    Result GetRawHeader(std::string& Out) const override
    {
        _ASSERT(0);
        return Result::ERR_FAIL;
    }

    Result GetRawBody(std::string_view& Out) const override
    {
        Out = content_;
        return Result::SS_OK;
    }

    const MultipartFormDataMap& GetFormDataMap() const override
    {
        return form_data_map_;
    }

    Result GetParameter(const std::string& Name, std::string& Out) const override
    {
        auto it = parameter_map_.find(Name);
        if (it == parameter_map_.end())
            return Result::ERR_FAIL;

        Out = it->second;
        return Result::SS_OK;
    }

    Result GetParameter(const std::string& Name, std::string_view& Out) const override
    {
        auto it = parameter_map_.find(Name);
        if (it == parameter_map_.end())
            return Result::ERR_FAIL;

        Out = it->second;
        return Result::SS_OK;
    }

    Result GetHeader(const std::string& Name, std::string& Out) const override
    {
        auto it = request_ptr_->header.find(Name);
        if (it == request_ptr_->header.end())
            return Result::ERR_FAIL;

        Out = it->second;
        return Result::SS_OK;
    }

    Result GetHeader(const std::string& Name, std::string_view& Out) const override
    {
        auto it = request_ptr_->header.find(Name);
        if (it == request_ptr_->header.end())
            return Result::ERR_FAIL;

        Out = it->second;
        return Result::SS_OK;
    }

    Result GetData(const std::string& Name, MultipartFormData& Out) const override
    {
        auto it = form_data_map_.find(Name);
        if (it == form_data_map_.end())
            return Result::ERR_FAIL;

        Out = it->second;
        return Result::SS_OK;
    }

public:
    const std::string& path() const override { return request_ptr_->path; };

public:
    explicit SwsRequest(std::shared_ptr<request_impl_type> request_ptr)
        : request_ptr_(request_ptr)
        , parameter_map_(request_ptr_->parse_query_string())
        , form_data_map_()
        , content_(request_ptr_->content.string())
    {
        int ret;

        std::string content_type;
        ret = GetHeader("content-type", content_type);
        if (ret < 0)
            return;

        if (!IsMultipartFormData(content_type))
            return;

        ret = ParseMultipartFormData(content_type,
            content_,
            form_data_map_);
    }

    ~SwsRequest() = default;

private:
    std::shared_ptr<request_impl_type> request_ptr_;
    SimpleWeb::CaseInsensitiveMultimap parameter_map_;
    std::multimap<std::string, MultipartFormData> form_data_map_;
    std::string content_;
};

class SwsResponse : public HttpResponse {
public:
    using server_impl_type = SimpleWeb::Server<SimpleWeb::HTTPS>;
    using response_impl_type = server_impl_type::Response;

public:
    Result SetHeader(const std::string& Name,
        const std::string& Value) override
    {
        header_.insert(std::make_pair(Name, Value));
        return Result::SS_OK;
    }

    Result SetContent(const char* Content) override
    {
        content_buf_.assign(Content);
        content_ref_ = content_buf_;
        return Result::SS_OK;
    }
    Result SetContent(const char* Content, size_t Length) override
    {
        content_buf_.assign(Content, Length);
        content_ref_ = content_buf_;
        return Result::SS_OK;
    }
    Result SetContent(const std::string& Content) override
    {
        content_buf_ = Content;
        content_ref_ = content_buf_;
        return Result::SS_OK;
    }
    Result SetContent(std::string&& Content) override
    {
        content_buf_ = Content;
        content_ref_ = content_buf_;
        return Result::SS_OK;
    }
    Result SetContent(std::string_view Content) override
    {
        content_ref_ = Content;
        return Result::SS_OK;
    }
    Result SetContentType(ContentType content_type) override
    {
        content_type_ = content_type;
        return Result::SS_OK;
    }

    Result SetResponseCode(unsigned int code) override
    {
        code_ = code;
        return Result::SS_OK;
    }

    Result GetRawHeader(std::string_view& Out) override
    {
        _ASSERT(0);
        return Result::ERR_FAIL;
    }
    Result GetRawContent(std::string_view& Out) override
    {
        _ASSERT(0);
        return Result::ERR_FAIL;
    }

public:
    explicit SwsResponse(std::shared_ptr<response_impl_type> response_ptr)
        : response_ptr_(response_ptr)
        , code_(200)
        , content_buf_()
        , content_ref_(content_buf_)
        , content_type_(websvc::CT_PLAIN_TEXT)
        , header_()
    {
    }

    ~SwsResponse()
    {
        SetHeader("content-type", ContentTypeEnumToString(content_type_));
        response_ptr_->write(SimpleWeb::StatusCode(code_), content_ref_, header_);
    }

private:
    std::shared_ptr<response_impl_type> response_ptr_;
    unsigned int code_;
    // when copy is unavoidable, copy content to content_buf_, and then
    // point content_ref_ to content_buf_. Otherwise just point content_ref_
    // to content.
    std::string content_buf_;
    std::string_view content_ref_;
    ContentType content_type_;
    SimpleWeb::CaseInsensitiveMultimap header_;
};


class SwsHttpServer : public HttpServer {
public:
    using server_impl_type = SimpleWeb::Server<SimpleWeb::HTTPS>;
    using request_impl_type = server_impl_type::Request;
    using response_impl_type = server_impl_type::Response;

public:
    Result Start(const HttpServerStartCallback& callback = nullptr) override
    {
        server_ptr_->start(callback);
        return Result::SS_OK;
    }
    Result Stop() override
    {
        server_ptr_->stop();
        return Result::SS_OK;
    }
    Result RegisterHandler(const std::string& method,
        const std::string& path,
        const HttpHandler& handler) override
    {
        server_ptr_->resource[path][method] =
            [handler](std::shared_ptr<response_impl_type> impl_response,
                std::shared_ptr<request_impl_type> impl_request) {
                    SwsRequest request(impl_request);
                    SwsResponse response(impl_response);

                    handler(request, response);
        };
        return Result::SS_OK;
    }

public:
    explicit SwsHttpServer(const HttpServerConfig& config)
    {
        CertSuit cst;
        auto r = GenerateCertificatePrivateKeyPair(cst);
        asio::const_buffer cert(cst.certificate.c_str(), cst.certificate.size());
        asio::const_buffer pkey(cst.private_key.c_str(), cst.private_key.size());
        server_ptr_ = std::make_shared<server_impl_type>(cert, pkey);

        server_ptr_->config.port = config.port;
        server_ptr_->config.thread_pool_size = config.thread_pool_size;
    }

    ~SwsHttpServer() = default;

private:
    std::shared_ptr<server_impl_type> server_ptr_;
};

} // namespace websvc
