#define WACK_EXPORT(name) __attribute__((export_name(name)))

int thing()
{
    return 1;
}

int xdp_drop()
{
    int (*fp)(void) = thing;
    return (fp)();
}
