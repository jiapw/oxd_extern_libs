#pragma once

#include <string>
#include <utility>

#include <openssl/conf.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

// FIXME: got something no compatible with openssl 3.0.
// ignore such deprecation temporarily.
#pragma warning(disable : 4996)


#include "cpp-httplib/httplib.h"

namespace websvc {

class Result {
public:
    enum Value : int {
        // ....
        ERR_FAIL = -1,
        SS_OK = 0,
        // ...
    };

public:
    Result() = default;
    constexpr Result(Value v)
        : _Value(v)
    {
    }

    // Allow switch and comparisons.
    constexpr operator Value() const { return _Value; }
    // Prevent usage: if(Result)
    explicit operator bool() const = delete;

    bool IsSucceeded() { return _Value >= SS_OK; }
    bool IsFailed() { return _Value <= ERR_FAIL; }

protected:
    Value _Value;
};

static_assert(std::is_pod<Result>::value);

struct CertSuit {
    std::string certificate;
    std::string private_key;
};

enum ContentType : int8_t {
    CT_PLAIN_TEXT = 0,
    CT_JSON,
    CT_WEBP,
    CT_BINARY
};

struct MultipartFormData {
    std::string content;
    std::string filename;
    std::string content_type;
};
using MultipartFormDataMap = std::multimap<std::string, MultipartFormData>;

inline bool IsMultipartFormData(const std::string& content_type)
{
    return !content_type.rfind("multipart/form-data", 0);
}

inline Result ParseMultipartFormData(const std::string& content_type, const std::string& body, MultipartFormDataMap& form_data_map)
{
    httplib::detail::MultipartFormDataParser parser;

    std::string boundary;
    if (!httplib::detail::parse_multipart_boundary(content_type, boundary))
        return Result::ERR_FAIL;
    parser.set_boundary(std::move(boundary));

    Result ret = Result::SS_OK;
    MultipartFormDataMap::iterator current_form_data = form_data_map.end();
    parser.parse(
        body.c_str(),
        body.size(),
        [&](const char* buf, size_t n) {
            if (current_form_data == form_data_map.end()) {
                ret = Result::ERR_FAIL;
                return false;
            }

            auto& content = current_form_data->second.content;
            if (content.size() + n > content.max_size()) {
                ret = Result::ERR_FAIL;
                return false;
            }

            content.append(buf, n);
            return true;
        },
        [&](const httplib::MultipartFormData& httplib_form_data) {
            MultipartFormData form_data;
            current_form_data = form_data_map.insert(std::make_pair(httplib_form_data.name, form_data));

            current_form_data->second.filename = httplib_form_data.filename;
            current_form_data->second.content_type = httplib_form_data.content_type;
            return true;
        });

    return ret;
}

/**
 * Generate Certificate and PrivateKey to memory dynamically.
 *
 * Reference:
 * https://opensource.apple.com/source/OpenSSL/OpenSSL-22/openssl/demos/x509/mkcert.c
 * https://stackoverflow.com/questions/256405/programmatically-create-x509-certificate-using-openssl
 * https://stackoverflow.com/questions/6877588/how-to-get-pem-encoded-x509-certificate-as-c-string-using-openssl
 */

const static int RSA_KEY_LENGTH = 4096;
const static int DAYS_VALID = 365;

Result GenerateCertificatePrivateKeyPair(CertSuit& out)
{
    std::string certificate;
    std::string private_key;

    std::unique_ptr<BIO, decltype(&::BIO_free)> bio_mem_ptr_certificate(
        BIO_new(BIO_s_mem()), ::BIO_free);
    std::unique_ptr<BIO, decltype(&::BIO_free)> bio_mem_ptr_private_key(
        BIO_new(BIO_s_mem()), ::BIO_free);

    if (bio_mem_ptr_certificate && bio_mem_ptr_private_key) {
        std::unique_ptr<RSA, decltype(&::RSA_free)> rsa{ RSA_new(), RSA_free };
        std::unique_ptr<BIGNUM, decltype(&::BN_free)> bn{ BN_new(), BN_free };

        BN_set_word(bn.get(), RSA_F4);
        int rsa_ok = RSA_generate_key_ex(rsa.get(), RSA_KEY_LENGTH, bn.get(), nullptr);
        if (rsa_ok) {
            std::unique_ptr<X509, decltype(&::X509_free)> cert{ X509_new(), X509_free };
            std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)> pkey{ EVP_PKEY_new(),
                EVP_PKEY_free };

            // The RSA structure will be automatically freed when the EVP_PKEY
            // structure is freed.
            EVP_PKEY_assign(pkey.get(), EVP_PKEY_RSA,
                reinterpret_cast<char*>(rsa.release()));
            // serial number
            ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);

            // now
            X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
            // accepts secs
            X509_gmtime_adj(X509_get_notAfter(cert.get()), DAYS_VALID * 24 * 3600);

            X509_set_pubkey(cert.get(), pkey.get());

            // 1 -- X509_NAME may disambig with wincrypt.h
            // 2 -- DO NO FREE the name internal pointer
            X509_name_st* name = X509_get_subject_name(cert.get());

            const unsigned char country[] = "USA";
            const unsigned char company[] = "Macro Hard";
            const unsigned char common_name[] = "localhost";

            X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, country, -1, -1, 0);
            X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, company, -1, -1, 0);
            X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, common_name, -1, -1,
                0);

            X509_set_issuer_name(cert.get(), name);
            // some hash type here
            X509_sign(cert.get(), pkey.get(), EVP_sha256());

            int private_key_mem_ok = PEM_write_bio_PrivateKey(bio_mem_ptr_private_key.get(), pkey.get(),
                nullptr, nullptr, 0, nullptr, nullptr);
            int certificate_mem_ok = PEM_write_bio_X509(bio_mem_ptr_certificate.get(), cert.get());

            if (private_key_mem_ok && certificate_mem_ok) {
                BUF_MEM* certificate_mem = nullptr;
                BUF_MEM* private_key_mem = nullptr;

                BIO_get_mem_ptr(bio_mem_ptr_certificate.get(), &certificate_mem);
                BIO_get_mem_ptr(bio_mem_ptr_private_key.get(), &private_key_mem);

                if (certificate_mem && certificate_mem->data && certificate_mem->length && private_key_mem && private_key_mem->data && private_key_mem->length) {
                    certificate = std::string(certificate_mem->data, certificate_mem->length);
                    private_key = std::string(private_key_mem->data, private_key_mem->length);

                    // std::cerr << "certificate: " << std::endl
                    //           << certificate << std::endl
                    //           << std::endl;

                    // std::cerr << "private_key: " << std::endl
                    //           << private_key << std::endl
                    //           << std::endl;
                }
            }
        }
    }

    out.certificate = certificate;
    out.private_key = private_key;
    return Result::SS_OK;
}



inline std::string ContentTypeEnumToString(ContentType content_type)
{
    _ASSERT(0);
    return "";
}

/*
    method Get,     support Content-Type: *
    method Post,    support Content-Type: multipart/form-data,

                    todo:   application/x-www-form-urlencoded,
                            Content-Type: application/json;charset=utf-8
                            Content-Type: text/plain;charset=utf-8
*/
class HttpRequest {
public:
    virtual Result Init(const std::string_view RawRequest) = 0;

    virtual Result GetRawHeader(std::string& Out) const = 0;
    virtual Result GetRawBody(std::string_view& Out) const = 0;
    virtual const MultipartFormDataMap& GetFormDataMap() const = 0;

    virtual Result GetParameter(const std::string& Name, std::string& Out) const = 0;
    virtual Result GetParameter(const std::string& Name, std::string_view& Out) const = 0;

    virtual Result GetHeader(const std::string& Name, std::string& Out) const = 0;
    virtual Result GetHeader(const std::string& Name, std::string_view& Out) const = 0;

    virtual Result GetData(const std::string& Name, MultipartFormData& Out) const = 0;

public:
    virtual const std::string& path() const = 0;
};

class HttpResponse {
public:
    virtual Result SetHeader(const std::string& Name, const std::string& Value) = 0;

    virtual Result SetContent(const char* Content) = 0;
    virtual Result SetContent(const char* Content, size_t Length) = 0;
    virtual Result SetContent(const std::string& Content) = 0;
    virtual Result SetContent(std::string&& Content) = 0;
    virtual Result SetContent(std::string_view Content) = 0;

    virtual Result SetContentType(ContentType content_type) = 0;

    virtual Result SetResponseCode(unsigned int code) = 0;

    virtual Result GetRawHeader(std::string_view& Out) = 0;
    virtual Result GetRawContent(std::string_view& Out) = 0;
};

using HttpHandler = std::function<Result(const HttpRequest&, HttpResponse&)>;
using HttpServerStartCallback = std::function<void(unsigned short /*port*/)>;

class HttpServer {
public:
    virtual Result Start(const HttpServerStartCallback& callback = nullptr) = 0;
    virtual Result Stop() = 0;
    virtual Result RegisterHandler(const std::string& method, const std::string& path, const HttpHandler& handler) = 0;
};

struct HttpServerConfig {
    uint16_t port;
    size_t thread_pool_size;
};

} // namespace websvc
