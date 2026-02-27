#include "common.h"

struct hello_s {
    int _0;
    int _1;
    union {
        int _2_i;
        long long _2_l;
    };
};

WACK_EXPORT("hook_xdp_drop")
int xdp_drop()
{
    volatile struct hello_s hello = {};
    hello._2_i = 11;
    hello._2_l = 11L;
    return hello._0 + hello._1;
}

int hook_something(struct hello_s* hello)
{
    hello->_0 += 4;
    return hello->_0;
}
