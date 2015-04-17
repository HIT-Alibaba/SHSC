#include "md5.h"

#include <string>
#include <iostream>

using namespace shsc;

int main() {
  std::string s = md5("hello");
  std::cout << s << std::endl;
  return 0;
}
