int hook_xdp_drop()
{
    volatile int a = 2;
    return a + a;
}
