import { FServer } from './server.js';
import init from 'tokamak-frost-wasm';

const port = process.env.PORT ? parseInt(process.env.PORT) : 9034;

// Initialize WASM module before starting server
init().then(() => {
    console.log('WASM module initialized.');
    try {
        new FServer(port);
    } catch (e) {
        console.error("Failed to start server:", e);
        process.exit(1);
    }
}).catch((e) => {
    console.error("Failed to initialize WASM:", e);
    process.exit(1);
});
