#pragma once

#include <algorithm>
#include <cstdint>
#include <type_traits>
#include <vector>
#include <string>

template<typename Integer,
    std::enable_if_t<std::is_integral<Integer>::value &&
        !std::is_signed<Integer>::value, bool> = true
>
int put_integer_big(Integer num, std::vector<unsigned char> &data) {
    size_t len = sizeof(Integer);
    size_t i = data.size();
   
    while(len--) {
        data.push_back(num);
        num >>= 8;
    }
    
    if constexpr (sizeof(Integer) > 1) {
        std::reverse(data.begin() + i, data.begin() + i + sizeof(Integer));
    }
    return sizeof(Integer);
}

template<typename Integer,
    std::enable_if_t<std::is_integral<Integer>::value &&
        !std::is_signed<Integer>::value, bool> = true
>
int get_integer_big(Integer *num, const std::vector<unsigned char> &data,
                size_t &idx) {
    size_t len = sizeof(Integer);
    Integer res = 0;
   
    while(len--) {
        res = (res << 8) | data[idx++];
    }
    return sizeof(Integer);
}

template<typename ALGO>
void ssh_algo_put(std::vector<unsigned char> data, 
                    const std::vector<ALGO> &algos) {
    uint32_t len = algos.size() - 1;
    for (auto &algo : algos) {
        len += algo.name.size();
    }

    int j = 0;
    for (auto &algo : algos) {
        if (j++) data.push_back(',');
        data.insert(data.end(), algo.name.begin(), algo.name.end());
    }
}