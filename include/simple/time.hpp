#pragma once

#include <thread>
#include <chrono>

namespace simple
{

namespace chrono = std::chrono;

template<typename T>
struct time
{
    static int64_t now()
    {
        auto now = chrono::system_clock::now();
        auto duration = now.time_since_epoch();
        return chrono::duration_cast<T>(duration).count();
    }

    static void sleep(int64_t t)
    {
        std::this_thread::sleep_for(T(t));
    }

    struct timestamp
    {
        timestamp()
        {
            reset_now();
        }
        void reset_now()
        {
            _val = chrono::system_clock::now();
        }
        int64_t elapsed()
        {
            auto duration = chrono::system_clock::now() - _val;
            return chrono::duration_cast<T>(duration).count();
        }
        int64_t value()
        {
            return chrono::duration_cast<T>(_val.time_since_epoch()).count();
        }
    protected:
        chrono::time_point<chrono::system_clock> _val;
    };
};

using time_in_nanoseconds = time<chrono::nanoseconds>;
using nanoseconds = time<chrono::nanoseconds>;

using time_in_microseconds = time<chrono::microseconds>;
using microseconds = time<chrono::microseconds>;

using time_in_milliseconds = time<chrono::milliseconds>;
using milliseconds = time<chrono::milliseconds>;
using ms = time<chrono::milliseconds>;

using time_in_seconds = time<chrono::seconds>;
using seconds = time<chrono::seconds>;


} // namespace simple
