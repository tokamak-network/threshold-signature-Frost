import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// Get directory of this file
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load wasm binary synchronously
const wasmPath = join(__dirname, 'pkg', 'tokamak_frost_wasm_bg.wasm');
const wasmBuffer = readFileSync(wasmPath);
const wasmModule = new WebAssembly.Module(wasmBuffer);

// Import the glue code setup function
import { __wbg_set_wasm } from './pkg/tokamak_frost_wasm_bg.js';

// We need to provide the imports that the wasm module expects
import * as bg from './pkg/tokamak_frost_wasm_bg.js';

// Build the imports object that the wasm module expects
const imports = {
    './tokamak_frost_wasm_bg.js': bg
};

// Create instance
const instance = new WebAssembly.Instance(wasmModule, imports);

// Set the wasm instance in the bg.js
__wbg_set_wasm(instance.exports);

// Call wasm start if it exists
if (instance.exports.__wbindgen_start) {
    instance.exports.__wbindgen_start();
}

// Re-export all wasm functions from bg.js
export * from './pkg/tokamak_frost_wasm_bg.js';

// No-op init function for compatibility
export default function init() {
    return Promise.resolve();
}
