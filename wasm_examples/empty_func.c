#include "common.h"

WACK_EXPORT("hook_xdp_drop")
int xdp_drop()
{
    return 0;
}
