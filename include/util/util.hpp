#pragma once

#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <algorithm>
#include <cstdint>
#include <type_traits>
#include <vector>
#include <string>

#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/integer.h>
#include <cryptopp/misc.h>

// String <=> Vec<char>.
std::string chvec2str(std::vector<unsigned char> data);
std::vector<unsigned char> str2chvec(std::string s);

// SecByteBlock <=> Integer.
CryptoPP::Integer byteblock_to_integer(const CryptoPP::SecByteBlock &block);
CryptoPP::SecByteBlock integer_to_byteblock(const CryptoPP::Integer &x);

// SecByteBlock <=> string.
std::string byteblock_to_string(const CryptoPP::SecByteBlock &block);
CryptoPP::SecByteBlock string_to_byteblock(const std::string &s);

// Printers.
void print_string_as_hex(std::string str);
void print_key_as_int(const CryptoPP::SecByteBlock &block);
void print_key_as_hex(const CryptoPP::SecByteBlock &block);

// Splitter.
std::vector<std::string> string_split(std::string str, char delimiter);

// my util
void put_string(std::vector<unsigned char> &data, const std::string& s);
std::string get_string(const std::vector<unsigned char> &data, size_t &idx);

void put_chvec(std::vector<unsigned char> &buf, std::vector<unsigned char> &data);

int buf_putsharedsecret_(std::vector<unsigned char> &buf, 
                        const unsigned char *x, long long len);

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
    *num = res;
    return sizeof(Integer);
}

void ssh_algo_put(std::vector<unsigned char>& data, 
                    const std::vector<std::string>& algos);

inline constexpr unsigned char operator "" _u8( unsigned long long arg ) noexcept
{
    return static_cast< unsigned char >( arg );
}

inline constexpr uint32_t operator "" _u32( unsigned long long arg ) noexcept
{
    return static_cast< uint32_t >( arg );
}

