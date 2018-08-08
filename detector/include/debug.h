#ifndef DEBUG_H
#define DEBUG_H

#include <iostream>

#ifndef NDEBUG
#define DEBUG(x) std::cout << x << std::endl
#define ISDEBUG
#else
#define DEBUG(x)
#endif

#endif
