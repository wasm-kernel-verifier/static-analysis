To build WASM examples:

```shell
> make rebuild-wasm
```

To run the checker on a WASM program:

```shell
> RUST_LOG=trace cargo run --release -- ./wasm_examples/empty_func.wasm
```

# Required tooling

 - Z3
 - wabt
 - LLVM
