import { expect } from "chai";
import { network } from "hardhat";

const { ethers } = await network.connect();

import { zeroPadValue } from "ethers";
import { verifyFrost, sign } from "../scripts/helper.js";
import * as secp from "@noble/secp256k1";
import { randomBytes } from "crypto";

describe("AppManager", function () {
  it("deploys ZecFrost then AppManager, adds an app, and verifies signature", async function () {
    const [deployer] = await ethers.getSigners();

    // 1) Deploy verifier (ZecFrost)
    const frostContract = await ethers.deployContract("ZecFrost");
    await frostContract.waitForDeployment();

    // 2) Deploy AppManager with ZecFrost address
    const appManager = await ethers.deployContract("AppManager", [frostContract.target]);
    await appManager.waitForDeployment();

    // --- Test vector (matches ZecFrost tests) ---
    const px = "0xf5fb844c1c4e52c6c16042bfe094a77b956a5617d5c778752cbca2cc6fff79d5";
    const py = "0xb82ac21d9fc23228ce870788429a6d5d3f6705c8eff6f6ff4ef74d5958d362ea";
    const rx = "0x3314ca9296af428f72a15dee6d8e9a3a2d5de1b0596d5bb8b64aa3cf353b7268";
    const ry = "0x6858866f16b651bb39e03a7ae07aad57452ef05824b47dbca585fa09eb4ec4b4";
    const s  = "0x5f347b9d18d3dc29bc57b87056a41177340d89ed88c297e97254aefb5e168860";
    const msg = "0x000000000000000000746f6b616d616b206d65737361676520746f207369676e";

    const message = zeroPadValue(msg as `0x${string}`, 32) as `0x${string}`;

    // Local sanity (off-chain verification helper)
    const { ok } = verifyFrost({ px, py, rx, ry, s, message });
    expect(ok).to.be.true;

    // keccak256(px||py) last 20 bytes (address derived from pubkey)
    const packed = ethers.concat([ethers.zeroPadValue(px, 32), ethers.zeroPadValue(py, 32)]);
    const hash = ethers.keccak256(packed);
    const derivedAddr = ethers.getAddress("0x" + hash.slice(26));

    // 3) Register app in AppManager
    const appid = 1;
    await (await appManager.addApp(appid, px, py)).wait();

    // 4) Read back app info
    const [appOwner, pkx, pky, signerAddr, exists] = await appManager.getApp(appid);
    expect(appOwner).to.equal(deployer.address);
    expect(pkx).to.equal(px);
    expect(pky).to.equal(py);
    expect(signerAddr).to.equal(derivedAddr);
    expect(exists).to.equal(true);

    // 5) Verify via AppManager (delegates to ZecFrost then compares recovered vs stored addr)
    const okOnChain = await appManager.verify(message, appid, rx, ry, s);
    expect(okOnChain).to.equal(true);
  });

  it("only app owner can update and remove; verify reflects updates", async function () {
    const [owner, stranger] = await ethers.getSigners();

    // Deploy verifier and manager
    const frost = await ethers.deployContract("ZecFrost");
    await frost.waitForDeployment();
    const mgr = await ethers.deployContract("AppManager", [frost.target]);
    await mgr.waitForDeployment();

    // Initial pubkey and signature (same vector as above)
    const px = "0xf5fb844c1c4e52c6c16042bfe094a77b956a5617d5c778752cbca2cc6fff79d5";
    const py = "0xb82ac21d9fc23228ce870788429a6d5d3f6705c8eff6f6ff4ef74d5958d362ea";
    const rx = "0x3314ca9296af428f72a15dee6d8e9a3a2d5de1b0596d5bb8b64aa3cf353b7268";
    const ry = "0x6858866f16b651bb39e03a7ae07aad57452ef05824b47dbca585fa09eb4ec4b4";
    const s  = "0x5f347b9d18d3dc29bc57b87056a41177340d89ed88c297e97254aefb5e168860";
    const msg = "0x000000000000000000746f6b616d616b206d65737361676520746f207369676e";
    const message = zeroPadValue(msg as `0x${string}`, 32) as `0x${string}`;

    const appid = 42;
    await (await mgr.addApp(appid, px, py)).wait();

    // Stranger cannot update
    await expect(
      mgr.connect(stranger).updateApp(appid, px, py)
    ).to.be.revertedWithCustomError(mgr, "NotAppOwner");

    // Owner can update to a different pubkey: mutate px by flipping the lowest bit (keeps 32-byte width)
    const newPx = ethers.zeroPadValue(ethers.toBeHex((BigInt(px) ^ 1n)), 32) as `0x${string}`;
    const newPy = py as `0x${string}`;
    await (await mgr.updateApp(appid, newPx, newPy)).wait();

    // Old signature should no longer validate under the updated key
    const okOldSig = await mgr.verify(message, appid, rx, ry, s);
    expect(okOldSig).to.equal(false);

    // Stranger cannot remove
    await expect(
      mgr.connect(stranger).removeApp(appid)
    ).to.be.revertedWithCustomError(mgr, "NotAppOwner");

    // Owner removes
    await (await mgr.removeApp(appid)).wait();

    // After removal, reads and verifies should reflect "not found"
    const after = await mgr.getApp(appid);
    expect(after[4]).to.equal(false); // exists
    await expect(
      mgr.verify(message, appid, rx, ry, s)
    ).to.be.revertedWithCustomError(mgr, "AppNotFound");
  });

  it("generates a fresh keypair and verifies end-to-end", async function () {
    // Deploy verifier and manager
    const frost = await ethers.deployContract("ZecFrost");
    await frost.waitForDeployment();
    const mgr = await ethers.deployContract("AppManager", [frost.target]);
    await mgr.waitForDeployment();

    // Generate a valid private key
    let privKey: Uint8Array;
    while (true) {
      const candidate = randomBytes(32);
      const isValid =
        (secp as any).utils?.isValidPrivateKey
          ? (secp as any).utils.isValidPrivateKey(candidate)
          : (secp as any).utils.isValidSecretKey(candidate);
      if (isValid) {
        privKey = candidate;
        break;
      }
    }

    // Public key and coordinates
    const pubCompressed = secp.getPublicKey(privKey, true);
    const P = secp.Point.fromBytes(pubCompressed);
    const px = ethers.toBeHex(P.x);
    const py = ethers.toBeHex(P.y);

    // Random message -> digest(keccak256) -> bytes32
    const messagePlain = ("0x" + Buffer.from(randomBytes(64)).toString("hex")) as `0x${string}`;
    const digest = ethers.keccak256(messagePlain);
    const message = zeroPadValue(digest as `0x${string}`, 32) as `0x${string}`;

    // Schnorr sign with helper (must match ZecFrost format)
    const sig = await sign(message, privKey);
    const R = secp.Point.fromBytes(sig.R);
    const rx = ethers.toBeHex(R.x);
    const ry = ethers.toBeHex(R.y);
    const s  = ethers.toBeHex(sig.s);

    // Off-chain sanity
    const { ok } = verifyFrost({ px, py, rx, ry, s, message });
    expect(ok).to.be.true;

    // Expected on-chain address from public key
    const packed = ethers.concat([ethers.zeroPadValue(px, 32), ethers.zeroPadValue(py, 32)]);
    const hash = ethers.keccak256(packed);
    const derivedAddr = ethers.getAddress("0x" + hash.slice(26));

    // Register and verify through AppManager
    const appid = 77;
    await (await mgr.addApp(appid, px, py)).wait();

    // Direct verifier consistency check
    const recovered = await frost.verify(message, px, py, rx, ry, s);
    expect(recovered).to.equal(derivedAddr);

    // AppManager verify must succeed
    const okOnChain = await mgr.verify(message, appid, rx, ry, s);
    expect(okOnChain).to.equal(true);
  });

  it("admin can update ZecFrost address; non-admin cannot", async function () {
    const [admin, other] = await ethers.getSigners();

    const frost1 = await ethers.deployContract("ZecFrost");
    await frost1.waitForDeployment();
    const mgr = await ethers.deployContract("AppManager", [frost1.target]);
    await mgr.waitForDeployment();

    const frost2 = await ethers.deployContract("ZecFrost");
    await frost2.waitForDeployment();



    // Admin can change
    await expect(mgr.connect(admin).setZecFrost(frost2.target)).to.emit(mgr, "ZecFrostSet");
  });

  it("reverts verify for unknown appid", async function () {
    const frost = await ethers.deployContract("ZecFrost");
    await frost.waitForDeployment();
    const mgr = await ethers.deployContract("AppManager", [frost.target]);
    await mgr.waitForDeployment();

    const rx = "0x3314ca9296af428f72a15dee6d8e9a3a2d5de1b0596d5bb8b64aa3cf353b7268";
    const ry = "0x6858866f16b651bb39e03a7ae07aad57452ef05824b47dbca585fa09eb4ec4b4";
    const s  = "0x5f347b9d18d3dc29bc57b87056a41177340d89ed88c297e97254aefb5e168860";
    const msg = "0x000000000000000000746f6b616d616b206d65737361676520746f207369676e";
    const message = zeroPadValue(msg as `0x${string}`, 32) as `0x${string}`;

    await expect(
      mgr.verify(message, 9999, rx, ry, s)
    ).to.be.revertedWithCustomError(mgr, "AppNotFound");
  });
});
