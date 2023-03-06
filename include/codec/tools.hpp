#pragma once
#include<string>
#include<string>
#include "cppcodec/base64_rfc4648.hpp"
#include "cppcodec/base64_url.hpp"
#include "cppcodec/base64_url_unpadded.hpp"

#include "cppcodec/base32_rfc4648.hpp"
#include "cppcodec/base32_hex.hpp"
#include "cppcodec/base32_crockford.hpp"

namespace codec
{

template<typename _RealCodec>
class Codec
{
public:
    static std::string Encode(std::string_view s)
    {
        return _RealCodec::encode(s.data(), s.size());
    }
    static std::string Decode(std::string_view s)
    {
        return _RealCodec::decode<std::string>(s.data(), s.size());
    }

    static std::string Encode(const std::string& s)
    {
        return _RealCodec::encode(s.data(), s.size());
    }
    static std::string Decode(const std::string& s)
    {
        return _RealCodec::decode<std::string>(s.data(), s.size());
    }

    static std::string Encode(const void* p, size_t len_by_byte)
    {
        return _RealCodec::encode((const char *)p, len_by_byte);
    }
    static std::string Decode(const void* p, size_t len_by_byte)
    {
        return _RealCodec::decode<std::string>((const char*)p, len_by_byte);
    }

    static std::string Encode(const char* p)
    {
        return Encode(std::string_view(p));
    }
    static std::string Decode(const char* p)
    {
        return Decode(std::string_view(p));
    }
    /*
    static std::string EncodeUrl(std::string_view s)
    {
        return cppcodec::base64_url::encode(s.data(), s.size());
    }
    static std::string DecodeUrl(std::string_view s)
    {
        return cppcodec::base64_url::decode<std::string>(s.data(), s.size());
    }
    */
};

using Base64 = Codec<cppcodec::base64_rfc4648>;
using Base64_Url = Codec<cppcodec::base64_url>;
using Base64_Unpadded = Codec <cppcodec::base64_url_unpadded>;

using Base32 = Codec<cppcodec::base32_rfc4648>;
using Base32_Hex = Codec<cppcodec::base32_hex>;
using Base32_Crockford = Codec <cppcodec::base32_crockford>;



}