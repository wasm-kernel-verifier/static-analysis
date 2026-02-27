int hook_if_simple()
{
    volatile int a = 2;
    if (a == 2) {
        return 0;
    } else {
        return a * 4;
    }
}
