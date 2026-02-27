__attribute__((import_module("wpf"), import_name("wpf_random_int")))
/// Returns a random integer in the range [a, b)
int wpf_random_int(int a, int b);

int hook_xdp_drop()
{
    return wpf_random_int(0, 10);
}
