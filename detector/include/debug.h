#ifndef DEBUG_H
#define DEBUG_H

#include <iostream>

#ifndef NDEBUG

#define DEBUG(x) std::cout << x << std::endl
#define ISDEBUG

#ifdef ISTRACE
#define TRACE(x) std::cout << x << std::endl
#else
#define TRACE(x)
#endif

#else
#define DEBUG(x)
#define TRACE(x)
#endif

#endif
