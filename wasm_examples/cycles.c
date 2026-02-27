#include "common.h"

int mutually_recursive_c();

int mutually_recursive_b()
{
    return mutually_recursive_c();
}

WACK_EXPORT("hook_mutually_recursive_a")
int mutually_recursive_a()
{
    return mutually_recursive_b();
}

int mutually_recursive_c()
{
    return mutually_recursive_a();
}

// ----------------------

WACK_EXPORT("hook_self_recursive")
int self_recursive()
{
    return self_recursive();
}
