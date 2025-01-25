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
		bool get_kv(std::string_view key, T& out) const
		{
			static_assert(
				(
					std::is_same_v<T, bool> ||
					std::is_same_v<T, int8_t> ||
					std::is_same_v<T, uint8_t> ||
					std::is_same_v<T, int16_t> ||
					std::is_same_v<T, uint16_t> ||
					std::is_same_v<T, int32_t> ||
					std::is_same_v<T, uint32_t> ||
					std::is_same_v<T, int64_t> ||
					std::is_same_v<T, uint64_t> ||
					std::is_same_v<T, float> ||
					std::is_same_v<T, double> ||
					std::is_same_v<T, std::string> ||
					std::is_same_v<T, nlohmann::json> ||
					std::is_same_v<T, simple::json>
				),
				"unsupported value type!"
			);

			nlohmann::json v;

			if (contains(key))
				v = this->operator[](key);
			else if(key.size() && key[0]=='/')
			{
				auto jp = nlohmann::json::json_pointer(std::string(key));
				if (contains(jp))
					v = this->operator[](jp);
			}

			if (v.is_null())
				return false;

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
			else if constexpr ( std::is_same_v<T, uint8_t>
				|| std::is_same_v<T, uint16_t>
				|| std::is_same_v<T, uint32_t> 
				||std::is_same_v<T, uint64_t>)
			{
				if (!v.is_number_unsigned())
					return false;
			}
			else if constexpr (std::is_same_v<T, int8_t>
				|| std::is_same_v<T, int16_t>
				|| std::is_same_v<T, int32_t>
				|| std::is_same_v<T, int64_t>)
			{
				if (!v.is_number_integer())
					return false;
			}
			else if constexpr (std::is_same_v<T, float>
				|| std::is_same_v<T, double>)
			{
				if (!v.is_number_float())
					return false;
			}
			else if constexpr (std::is_same_v<T, nlohmann::json> || std::is_same_v<T, json>)
			{
				if (!v.is_object() && !v.is_array())
					return false;
			}

			out = v;
			
			return true;
		}
		template<typename T>
		bool get_kv(std::string_view key, T& out, const T& default_v) const
		{
			if (!get_kv(key, out))
				out = default_v;
			return true;
		}
		bool get_kv(std::string_view key, std::string& out, std::string_view default_v) const
		{
			if (!get_kv(key, out))
				out = default_v;
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