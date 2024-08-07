#pragma once

#include "../nlohmann/json.hpp" // nlohmann::json

#ifndef INCLUDE_NLOHMANN_JSON_HPP_
#pragma error "simple_json need nlohmann::json!"
#endif

namespace simple {

	class json : public nlohmann::json
	{
	public:
		json() {};
		json(std::string_view input) 
		{ 
			if (!input.empty()) 
				parse(input); 
		}
		json(const char* data, size_t len) 
		{ 
			std::string_view input = std::string_view(data, len);
			if (!input.empty()) 
				parse(input);
		}
		json& operator=(const nlohmann::json& other)
		{
			*(nlohmann::json*)this = other;
			return *this;
		}
		bool parse(std::string_view input)
		{
			*(nlohmann::json*)this = nlohmann::json::parse(input, nullptr, false);
			return is_valid();
		}
		bool is_valid() const
		{
			return !is_discarded();
		}
		template<typename T>
		bool get_kv(std::string_view key, T& out)
		{
			if (!contains(key))
				return false;

			auto& v = this->operator[](key);

			static_assert( 
				(
					std::is_same_v<T, bool> ||
					std::is_same_v<T, int64_t> ||
					std::is_same_v<T, uint64_t> ||
					std::is_same_v<T, float> ||
					std::is_same_v<T, std::string> ||
					std::is_same_v<T, nlohmann::json> || 
					std::is_same_v<T, simple::json>
				),
				"unsupported value type!"
			);

			if constexpr(std::is_same_v<T, std::string>)
			{
				if (!v.is_string())
					return false;
			}
			else if constexpr (std::is_same_v<T, bool>)
			{
				if (!v.is_boolean())
					return false;
			}
			else if constexpr (std::is_same_v<T, uint64_t>)
			{
				if (!v.is_number_unsigned())
					return false;
			}
			else if constexpr (std::is_same_v<T, int64_t>)
			{
				if (!v.is_number_integer())
					return false;
			}
			else if constexpr (std::is_same_v<T, float>)
			{
				if (!v.is_number_float())
					return false;
			}
			else if constexpr (std::is_same_v<T, nlohmann::json> || std::is_same_v<T, json>)
			{
				if (!v.is_object())
					return false;
			}

			out = v;
			
			return true;
		}
		static json& from_nlohmann_json(nlohmann::json& j)
		{
			return *(json*)&j;
		}
		nlohmann::json& to_nlohmann_json()
		{
			return *(nlohmann::json*)this;
		}
	};

} // namespace simple