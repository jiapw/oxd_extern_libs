#pragma once

#include <system_error>
#include <string>

#define NAME_VALUE(name, value, str) name = value,
#define NAME_STR(name, value, str) case type::name : return str;

#define MAKE_ENUM(TYPENAME, LIST)   \
enum class TYPENAME {   \
    LIST(NAME_VALUE)    \
};  //  MAKE_ENUM

#define MAKE_CATELOGY(TYPENAME, LIST)   \
struct TYPENAME##Category : std::error_category {    \
    const char* name() const noexcept override { \
        return #TYPENAME;   \
    }   \
    std::string message(int ev) const override { \
        using type = TYPENAME;  \
        switch (static_cast<TYPENAME>(ev)) { \
            LIST(NAME_STR)  \
            default: return "Unknown error";    \
        }   \
    }   \
    static const TYPENAME##Category& SingleInstance() {  \
        static TYPENAME##Category si;   \
        return si;  \
    }   \
};  //  MAKE_CATELOGY


#define MAKE_STD_ERROR_CODE(TYPENAME)   \
inline std::error_code make_error_code(TYPENAME e) {    \
    return { static_cast<int>(e), TYPENAME##Category::SingleInstance() }; \
}   //  MAKE_STD_ERROR_CODE


#define REGISTER_ERROR_LIST(CLASSNAME, LIST, NAMESPACE) \
namespace NAMESPACE {    \
    MAKE_ENUM(CLASSNAME, LIST)      \
    MAKE_CATELOGY(CLASSNAME, LIST)  \
    MAKE_STD_ERROR_CODE(CLASSNAME)  \
}   \
namespace std {   \
    template <> struct is_error_code_enum<NAMESPACE::CLASSNAME> : true_type {}; \
}   //  REGISTER_ERROR_LIST


