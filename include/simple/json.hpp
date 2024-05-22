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
		json(std::string_view input) { if (!input.empty()) parse(input); }

		bool parse(std::string_view input)
		{
			*(nlohmann::json*)this = nlohmann::json::parse(input, nullptr, false);
			return is_valid();
		}
		bool is_valid() const
		{
			return !is_discarded();
		}
		bool get_kv_string(std::string_view key, std::string& out)
		{
			if (!contains(key))
				return false;

			auto& v = this->operator[](key);
			if (!v.is_string())
				return false;

			out = v;
			return true;
		}
		static json& from_nlohmann_json(nlohmann::json& j)
		{
			return *(json*)&j;
		}
	};

} // namespace simple