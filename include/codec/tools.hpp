#pragma once
#include<string>
#include "cppcodec/base64_rfc4648.hpp"
#include "cppcodec/base64_url.hpp"

namespace codec
{

class Base64
{
public:
    static std::string Encode(std::string_view s)
    {
        return cppcodec::base64_rfc4648::encode(s.data(), s.size());
    }
    static std::string<uint8_t> Decode(std::string_view s)
    {
        return cppcodec::base64_rfc4648::decode(s.data(), s.size());
    }
    static std::vector<uint8_t> Decode(std::string_view s)
    {
        return cppcodec::base64_rfc4648::decode(s.data(), s.size());
    }
    static std::string EncodeUrl(std::string_view s)
    {
        return cppcodec::base64_url::encode(s.data(), s.size());
    }
};

}