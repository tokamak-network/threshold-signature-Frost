// scripts/verify-signature.ts
// Script runner variant (env-driven) for verifying a Rust-produced signature.json on-chain.
// Preferred usage is the Hardhat task (see hardhat.config.ts):
//   npx hardhat verify-signature --network hardhat --sig ../run1/signature.json [--address 0x...]
// This script variant avoids Hardhat arg parsing; pass values via environment variables:
//   SIG=../run1/signature.json ADDRESS=0xYourZecFrost npx hardhat run scripts/verify-signature.ts --network hardhat

import { network } from "hardhat";

const { ethers } = await network.connect({
    network: "hardhatOp",
    chainType: "op",
});
import fs from "fs/promises";
import path from "path";

function usageAndExit(msg?: string): never {
    if (msg) console.error(msg);
    console.error(
        "\nUsage (script): SIG=<path/to/signature.json> [ADDRESS=<ZecFrostAddress>] npx hardhat run scripts/verify-signature.ts --network <net>\n"
    );
    process.exit(1);
}

function toBytes32(hexLike: string): string {
    if (!hexLike) throw new Error("empty hex input");
    let h = hexLike.toLowerCase();
    if (h.startsWith("0x")) h = h.slice(2);
    if (h.length > 64) throw new Error(`hex length > 32 bytes: ${h.length / 2} bytes`);
    return "0x" + h.padStart(64, "0");
}

async function main() {
    const sigPath = process.env.SIG; // avoid Hardhat CLI arg parsing
    const address = process.env.ADDRESS;
    if (!sigPath) usageAndExit("Missing SIG env var pointing to signature.json");

    const fullPath = path.resolve(process.cwd(), sigPath);
    const raw = await fs.readFile(fullPath, "utf8");
    const sig = JSON.parse(raw);

    // Expecting fields written by the Rust aggregator:
    // { px, py, rx, ry, s, message, group_id, signature_bincode_hex }
    const px = toBytes32(sig.px);
    const py = toBytes32(sig.py);
    const rx = toBytes32(sig.rx);
    const ry = toBytes32(sig.ry);
    const s  = toBytes32(sig.s);
    const m  = toBytes32(sig.message);

    const [signer] = await ethers.getSigners();
    console.log("Using signer:", signer.address);

    let zf: any;
    const ZF = await ethers.getContractFactory("ZecFrost", signer);
    if (address) {
        console.log("Attaching to ZecFrost at", address);
        zf = ZF.attach(address);
    } else {
        console.log("Deploying ZecFrost…");
        zf = await ZF.deploy();
        await zf.waitForDeployment();
        console.log("ZecFrost deployed at", await zf.getAddress());
    }

    // Solidity:
    //   function verify(bytes32 px, bytes32 py, bytes32 rx, bytes32 ry, bytes32 s, bytes32 m) external view returns (bool);
    console.log("Calling ZecFrost.verify(px,py,rx,ry,s,m)…");
    const ok: boolean = await zf.verify(px, py, rx, ry, s, m);
    console.log("On-chain verify:", ok ? "✅ valid" : "❌ invalid");
    if (!ok) process.exitCode = 1;
}

main().catch((e) => {
    console.error(e);
    process.exit(1);
});
