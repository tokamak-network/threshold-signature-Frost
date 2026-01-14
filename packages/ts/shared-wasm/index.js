// Re-export all wasm functions
export * from './pkg/tokamak_frost_wasm.js';

// No-op init function for compatibility with web target API
// The bundler target auto-initializes, so init() is not needed
export default function init() {
    return Promise.resolve();
}
