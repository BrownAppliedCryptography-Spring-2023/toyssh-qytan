#include <vector>
// #include <cryptopp/config_int.h>
#include "util/util.hpp"
#include "util/logger.hpp"


/**
 * Convert char vec to string.
 */
std::string chvec2str(std::vector<unsigned char> data) {
  std::string s(data.begin(), data.end());
  return s;
}

/**
 * Convert string to char vec.
 */
std::vector<unsigned char> str2chvec(std::string s) {
  std::vector<unsigned char> v(s.begin(), s.end());
  return v;
}

/**
 * Converts a byte block into an integer.
 */
CryptoPP::Integer byteblock_to_integer(const CryptoPP::SecByteBlock &block) {
  return CryptoPP::Integer(block, block.size());
}

/**
 * Converts an integer into a byte block.
 */
CryptoPP::SecByteBlock integer_to_byteblock(const CryptoPP::Integer &x) {
  size_t encodedSize = x.MinEncodedSize(CryptoPP::Integer::UNSIGNED);
  CryptoPP::SecByteBlock bytes(encodedSize);
  x.Encode(bytes.BytePtr(), encodedSize, CryptoPP::Integer::UNSIGNED);
  return bytes;
}

/**
 * Converts a byte block into a string.
 */
std::string byteblock_to_string(const CryptoPP::SecByteBlock &block) {
  return std::string(block.begin(), block.end());
}

/**
 * Converts a string into a byte block.
 */
CryptoPP::SecByteBlock string_to_byteblock(const std::string &s) {
  CryptoPP::SecByteBlock block(reinterpret_cast<const CryptoPP::byte *>(&s[0]), s.size());
  return block;
}

/**
 * Given a string, it prints its hex representation of the raw bytes it
 * contains. Used for debugging.
 */
void print_string_as_hex(std::string str) {
  for (int i = 0; i < str.length(); i++) {
    std::cout << std::hex << std::setfill('0') << std::setw(2)
              << static_cast<int>(str[i]) << " ";
  }
  std::cout << std::endl;
}

/**
 * Prints contents as integer
 */
void print_key_as_int(const CryptoPP::SecByteBlock &block) {
  std::cout << byteblock_to_integer(block) << std::endl;
}

/**
 * Prints contents as hex.
 */
void print_key_as_hex(const CryptoPP::SecByteBlock &block) {
  std::string result;
  CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(result));

  encoder.Put(block, block.size());
  encoder.MessageEnd();

  std::cout << result << std::endl;
}

/**
 * Split a string.
 */
std::vector<std::string> string_split(std::string str, char delimiter) {
  std::vector<std::string> result;
  // construct a stream from the string
  std::stringstream ss(str);
  std::string s;
  while (std::getline(ss, s, delimiter)) {
    result.push_back(s);
  }
  return result;
}
void ssh_algo_put(std::vector<unsigned char>& data, 
                    const std::vector<std::string>& algos) {
    uint32_t len = algos.size() - 1;
    for (auto &algo : algos) {
        len += algo.size();
    }

    put_integer_big(len, data);

    int j = 0;
    for (auto &algo : algos) {
        if (j++) data.push_back(',');
        data.insert(data.end(), algo.begin(), algo.end());
    }
}

void put_string(std::vector<unsigned char> &data, const std::string& s) {
    uint32_t len = s.size();
    put_integer_big(len, data);
    if (s.size()) {
        data.insert(data.end(), s.begin(), s.end());
    }
}

std::string get_string(const std::vector<unsigned char> &data, size_t &idx) {
    uint32_t len;
    get_integer_big(&len, data, idx);

    std::string s(data.begin() + idx, data.begin() + idx + len);
    idx += len;
    return s;
}

void put_chvec(std::vector<unsigned char> &data, std::vector<unsigned char> &vec) {
    put_integer_big(static_cast<uint32_t>(vec.size()), data);
    data.insert(data.end(), vec.begin(), vec.end());
}

/*
Put SSH shared secret (bignum formated into wire format)
*/
int buf_putsharedsecret_(std::vector<unsigned char> &buf, 
                      const unsigned char *x, long long len) {

    long long pos;
    for (pos = 0; pos < len; ++pos) if (x[pos]) break;

    if (x[pos] & 0x80) {
        put_integer_big(static_cast<uint32_t>(len - pos + 1), buf);
        put_integer_big(0_u8, buf);
    }
    else {
        put_integer_big(static_cast<uint32_t>(len - pos + 0), buf);
    }
    
    while (pos < len) buf.push_back(x[pos++]);
    return len;
}
