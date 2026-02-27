int thing()
{
    return 1;
}

int thing2()
{
    return 2;
}

int hook_xdp_drop()
{
    int (*fp)(void) = thing;
    // Force generation of `call_indirect` operator
    asm("" : "+r"(fp));
    return (fp)();
}
