#include <vector>

#include "util/util.hpp"
#include "util/logger.hpp"

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
