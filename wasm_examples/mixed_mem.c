int hook__test_byte_aligned_access_codegen(int i)
{
    char array[4] = { 0, 17, 43, 25 };
    return array[i];
}
