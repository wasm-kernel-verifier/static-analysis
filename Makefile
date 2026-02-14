.PHONY: rebuild-wasm
rebuild-wasm:
	$(MAKE) -C wasm_examples/ clean
	$(MAKE) -C wasm_examples/ all
