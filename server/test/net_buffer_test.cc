#include "network/buffer.h"
#include <string>
#include <stdio.h>

using namespace shsc;

int main() {
    Buffer buffer;
    buffer.Append("12345", 5);
    buffer.Append("12345", 5);

    std::string s = buffer.TakeAsString();
    printf("result=%s, expected=%s\n", 
            s.c_str(), "1234512345");
    printf("buffer.size=%zd, expected=%d\n", 
            buffer.WritableBytes(), 10);
}
