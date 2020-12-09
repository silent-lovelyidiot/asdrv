#ifndef __CONSTEXPR_H__
#define __CONSTEXPR_H__

namespace {
template<int V>
class Int32ReverseW {
 public:
  enum {_L = V & 0xff, _H = (V & 0x0000ff00) >> 8, Value = (_L << 16) | _H};
  static_assert(!(V & ~0xffff), "V must <= 0xffff");
};



constexpr int Int32ReverseCompute(int Val24, int Val16, int Val8, int Val) {
  return Val24 ? ((Val << 24) | (Val8 << 16) | (Val16 << 8) | (Val24)) :
           Val16 ? ((Val << 16) | (Val8 << 8) | (Val16)) :
             Val8 ? ((Val << 8) | (Val8)) :
               Val;
}

template<int V>
class Int32ReverseA {
 public:
  enum {
    Value = Int32ReverseCompute((V & 0xff000000) >> 24, (V & 0x00ff0000) >> 16, (V & 0x0000ff00) >> 8, V & 0x000000ff)
  };
};

constexpr int LineNumber(const int Line) {
  return Int32ReverseCompute((Line / 1000) + '0', Line / 100 % 10 + '0', Line / 10 % 10 + '0', Line % 10 + '0');
}

}

#define LINE_NUMBER LineNumber(__LINE__)

#define   RA(x)  Int32ReverseA<(x)>::Value
#define   RW(x)  Int32ReverseW<(x)>::Value



#endif // !__CONSTEXPR_H__