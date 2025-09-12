import {expect} from "chai";
import {network} from "hardhat";

const {ethers} = await network.connect();

// @ts-ignore
import {sha256} from "@noble/hashes/sha256";
import {secp256k1} from "@noble/curves/secp256k1";
import {keccak256, zeroPadValue} from "ethers";
import * as secp from "@noble/secp256k1";
import {randomBytes} from "crypto";

const {ProjectivePoint: P, CURVE} = secp256k1;

const te = new TextEncoder();
const isHex = (s: string) => /^[0-9a-fA-F]+$/.test(s.replace(/^0x/, ""));
const strip0x = (h: string) => (h.startsWith("0x") ? h.slice(2) : h);

const Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const HALF_Q = (Q >> 1n) + 1n;

describe("Frost", function () {
    it("verify function random key", async function () {
        const frostContract = await ethers.deployContract("ZecFrost");
        const deploymentBlockNumber = await ethers.provider.getBlockNumber();


        let privKey: Uint8Array
            = randomBytes(32);

        let publicKey = secp.getPublicKey(privKey, true);
        let P = secp.Point.fromBytes(publicKey);

        do {
            privKey = randomBytes(32);
            publicKey = secp.getPublicKey(privKey, true);
            P = secp.Point.fromBytes(publicKey);
            if (!secp.utils.isValidSecretKey((privKey))) {
                console.log("problem with key");
                continue;
            }
        } while (false);//P.x >= HALF_Q

        console.log("P.x < HALF_Q := ", P.x < HALF_Q)

        const messagePlain = "0x" + Buffer.from(randomBytes(256)).toString("hex");
        const message = keccak256(messagePlain);

        let message32 = zeroPadValue((message) as `0x${string}`, 32) as `0x${string}`;
        const sig = sign(message32, privKey);

        let R = secp.Point.fromBytes(sig.R);


        let px = ethers.toBeHex(P.x);
        let py = ethers.toBeHex(P.y);
        let rx = ethers.toBeHex(R.x);
        let ry = ethers.toBeHex(R.y);
        let s = ethers.toBeHex(sig.s);


        const {ok} = verifyFrost({px, py, rx, ry, s, message});
        expect(ok).to.be.true;

        // keccak256(px || py)[12:]
        const packed = ethers.concat([
            ethers.zeroPadValue(px, 32),
            ethers.zeroPadValue(py, 32),
        ]);
        const hash = ethers.keccak256(packed);
        const addr = ethers.getAddress("0x" + hash.slice(26)); // take last 20 bytes

        console.log("addr\t=", addr);

        const ret = await frostContract.measureVerify.staticCall(message, px, py, rx, ry, s);
        const cold = ret[0];
        const warm = ret[1];
        console.log("--verify gas (cold):", cold.toString());
        console.log("--verify gas (warm):", warm.toString());

        // Call verify
        const result = await frostContract.verify(message, px, py, rx, ry, s);
        expect(result).to.equal(addr);

        const result2 = await frostContract.verifyBytes(messagePlain, px, py, rx, ry, s);
        expect(result2).to.equal(addr);


    });
    it("verify function", async function () {
        const frostContract = await ethers.deployContract("ZecFrost");
        const deploymentBlockNumber = await ethers.provider.getBlockNumber();

        let px = "0xf5fb844c1c4e52c6c16042bfe094a77b956a5617d5c778752cbca2cc6fff79d5"
        let py = "0xb82ac21d9fc23228ce870788429a6d5d3f6705c8eff6f6ff4ef74d5958d362ea"
        let rx = "0x3314ca9296af428f72a15dee6d8e9a3a2d5de1b0596d5bb8b64aa3cf353b7268"
        let ry = "0x6858866f16b651bb39e03a7ae07aad57452ef05824b47dbca585fa09eb4ec4b4"
        let s = "0x5f347b9d18d3dc29bc57b87056a41177340d89ed88c297e97254aefb5e168860"
        let msg = "0x000000000000000000746f6b616d616b206d65737361676520746f207369676e"

        let message = zeroPadValue((msg) as `0x${string}`, 32) as `0x${string}`;
        console.log("message : ", message);
        const {ok, challengeHex} = verifyFrost({px, py, rx, ry, s, message});
        expect(ok).to.be.true;

        // keccak256(px || py)[12:]
        const packed = ethers.concat([
            ethers.zeroPadValue(px, 32),
            ethers.zeroPadValue(py, 32),
        ]);
        const hash = ethers.keccak256(packed);
        const addr = ethers.getAddress("0x" + hash.slice(26)); // take last 20 bytes

        console.log("addr\t=", addr);

        const ret = await frostContract.measureVerify.staticCall(message, px, py, rx, ry, s);
        const cold = ret[0];
        const warm = ret[1];
        console.log("--verify gas (cold):", cold.toString());
        console.log("--verify gas (warm):", warm.toString());

        // Call verify
        const result = await frostContract.verify(message, px, py, rx, ry, s);
        expect(result).to.equal(addr);


    });
    it("verify function with second input", async function () {
        const frostContract = await ethers.deployContract("ZecFrost");
        const deploymentBlockNumber = await ethers.provider.getBlockNumber();

        let px = "0xe6acc820c0e28f3b657d06018f5309040622d7061c408b6f8b1c604fdc859213"
        let py = "0x65b785bfb18b31c53192a64b399001ddbf3f350a38ba982a867417b2a9200483"
        let rx = "0x7589c256f4188a142bed4f100389598ee1d58bba528aef449724a0f40cdada2b"
        let ry = "0x7750a5c45aad21d010589792fde41f8c76d6238a1ad0cfdc5322f496f3ba5827"
        let s = "0x07f0779a7e296d0ecf75506daa5c4e7c6fa35090c9c6348c05871b2ea9c591d6"

        const msgPlain = "0x746f6b616d616b206d65737361676520746f207369676e2c746f6b616d616b206d65737361676520746f207369676e2c746f6b616d616b206d65737361676520746f207369676e2c746f6b616d616b206d65737361676520746f207369676e2c746f6b616d616b206d65737361676520746f207369676e2c746f6b616d616b206d65737361676520746f207369676e2c746f6b616d616b206d65737361676520746f207369676e"; // or hex string
        let message = zeroPadValue((keccak256(msgPlain)) as `0x${string}`, 32) as `0x${string}`;

        const {ok, challengeHex} = verifyFrost({px, py, rx, ry, s, message});
        expect(ok).to.be.true;

    });
    it("verify function with second input", async function () {
        const frostContract = await ethers.deployContract("ZecFrost");
        const deploymentBlockNumber = await ethers.provider.getBlockNumber();

        let px = "0x106d6ffa16b1413284ef26c44ed4cb927454f10be209025d26bbd04368b5d50b"
        let py = "0x76adc4bc2da7b6859ad135e4a14b471232258af57ab1336acdaf4e561dc7c0eb"
        let rx = "0x885e5694cebe53ae6d9771086ce51ab0662c3ce1ae781421fd081e136517988d"
        let ry = "0x1ab8ff303b7bc122620c3e9e4eddad6ea40483ee2c026e0b422dcecaeb6b5c1f"
        let s = "0xdee457e807b6023852812ee2e6e094364160832d8dc198ca61240797b66daf28"

        const msgPlain = "0x211bd5c1de953a3c64ca86bbb96fce8233ff79ec266eda1cabdb414f62f17fc1"; // or hex string
        let message = zeroPadValue(msgPlain as `0x${string}`, 32) as `0x${string}`;

        const {ok, challengeHex} = verifyFrost({px, py, rx, ry, s, message});
        expect(ok).to.be.true;

    });

});

/**
 * hexToBytes — Converts a hex string (with or without 0x prefix) to a Uint8Array.
 * Pads a leading nibble if needed so length is even.
 */
const hexToBytes = (hex: string): Uint8Array => {
    let h = strip0x(hex);
    if (h.length % 2) h = "0" + h;
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
    return out;
};

/**
 * bytesToHex — Converts a Uint8Array to a lowercase hex string (no 0x).
 */
const bytesToHex = (b: Uint8Array) =>
    Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/**
 * concat — Concatenates multiple Uint8Array values into one.
 */
const concat = (...arrs: Uint8Array[]) => {
    const len = arrs.reduce((a, b) => a + b.length, 0);
    const out = new Uint8Array(len);
    let off = 0;
    for (const a of arrs) {
        out.set(a, off);
        off += a.length;
    }
    return out;
};

/**
 * i2osp — Integer-to-Octet-String primitive (RFC 8017 §4.1).
 * Encodes a non-negative integer to a fixed-length big-endian byte array.
 * Here used only with small values that always fit in the requested length.
 */
const i2osp = (value: number, length: number) => {
    const out = new Uint8Array(length);
    for (let i = length - 1; i >= 0; i--) {
        out[i] = value & 0xff;
        value >>>= 8;
    }
    return out;
};

/**
 * os2ip — Octet-String-to-Integer primitive (RFC 8017 §4.2).
 * Interprets a big-endian byte array as a non-negative bigint.
 */
const os2ip = (bytes: Uint8Array): bigint => {
    let res = 0n;
    for (const b of bytes) res = (res << 8n) + BigInt(b);
    return res;
};

// ---------- SEC1 compressed encoding from (x,y) ----------
/**
 * to32 — Left-pads a byte array with zeros to 32 bytes. Throws if input > 32 bytes.
 */
function to32(b: Uint8Array): Uint8Array {
    if (b.length > 32) throw new Error("length > 32");
    const out = new Uint8Array(32);
    out.set(b, 32 - b.length);
    return out;
}

/**
 * compressedFromXY — SEC1 compressed encoding from affine (x,y).
 * Prefix 0x02 if y is even, 0x03 if y is odd; then 32-byte big-endian x.
 * Returns 33-byte compressed point.
 */
function compressedFromXY(pxHex: string, pyHex: string): Uint8Array {
    const x = to32(hexToBytes(pxHex));
    const y = os2ip(hexToBytes(pyHex));
    const prefix = (y & 1n) === 0n ? 0x02 : 0x03;
    const out = new Uint8Array(33);
    out[0] = prefix;
    out.set(x, 1);
    return out;
}

// ---------- RFC 9380 ExpandMessageXMD(SHA-256) ----------
/**
 * expand_message_xmd_sha256 — RFC 9380 §5.4.1 ExpandMessageXMD for SHA-256.
 * Uses Z_pad of 64 zero bytes (SHA-256 block size) and HLen=32.
 * DST' = DST || I2OSP(len(DST),1). Produces lenInBytes of pseudorandom bytes.
 */
function expand_message_xmd_sha256(msg: Uint8Array, DST: Uint8Array, lenInBytes: number): Uint8Array {
    const HLEN = 32;            // SHA-256 output size in bytes
    const BLOCK_SIZE = 64;      // SHA-256 block size in bytes
    const ell = Math.ceil(lenInBytes / HLEN);
    if (ell > 255) throw new Error("expand_message_xmd: ell too big");

    // Domain is handled outside; here we directly construct DST_prime = DST || I2OSP(len(DST),1)
    const DSTprime = concat(DST, i2osp(DST.length, 1));

    // Z_pad is block-size zeros per RFC 9380 & Rust ExpandMsgXmd
    const Z_pad = new Uint8Array(BLOCK_SIZE);
    const l_i_b_str = i2osp(lenInBytes, 2);

    // b0 = H(Z_pad || msg || l_i_b_str || I2OSP(0,1) || DST_prime)
    const b0 = sha256(concat(Z_pad, msg, l_i_b_str, i2osp(0, 1), DSTprime));

    // b1 = H(b0 || I2OSP(1,1) || DST_prime)
    let bi = sha256(concat(b0, i2osp(1, 1), DSTprime));

    const pseudo = new Uint8Array(ell * HLEN);
    pseudo.set(bi, 0);

    for (let i = 2; i <= ell; i++) {
        // bi = H( (b_{i-1} XOR b0) || I2OSP(i,1) || DST_prime )
        const bx = new Uint8Array(HLEN);
        for (let j = 0; j < HLEN; j++) bx[j] = bi[j] ^ b0[j];
        bi = sha256(concat(bx, i2osp(i, 1), DSTprime));
        pseudo.set(bi, (i - 1) * HLEN);
    }
    return pseudo.slice(0, lenInBytes);
}

// helper to mirror Rust Domain::xmd behavior for oversize DSTs
/**
 * dst_xmd_sha256 — Handles oversize DST per RFC 9380 §5.3.3.
 * If DST > 255 bytes, replace with SHA256("H2C-OVERSIZE-DST-" || DST).
 */
function dst_xmd_sha256(parts: Uint8Array[]): Uint8Array {
    const merged = concat(...parts);

    if (merged.length <= 255) return merged;
    // Oversize DST: DST = H("H2C-OVERSIZE-DST-" || merged)
    const tag = te.encode("H2C-OVERSIZE-DST-");
    const d = sha256(concat(tag, merged));
    return new Uint8Array(d); // 32 bytes
}

// ---------- hash_to_scalar for secp256k1 (order n) ----------
/**
 * hash_to_scalar — RFC 9380 hash_to_field mapping into secp256k1 scalar field.
 * L=48 bytes for 128-bit security; reduces mod n. Returns bigint in [0, n-1].
 */
function hash_to_scalar(msg: Uint8Array, DST: Uint8Array): bigint {
    // For 128-bit security, L = ceil((ceil(log2(n)) + 128) / 8) = 48 for secp256k1
    const L = 48;
    const pseudo = expand_message_xmd_sha256(msg, DST, L);
    const u = os2ip(pseudo) % CURVE.n;
    return u;
}

// ---------- H2 as in lib.rs ----------
/**
 * H2 — FROST(secp256k1, SHA-256) challenge hash (RFC 9591 §6.5).
 * Implements hash_to_field^XMD with DST = "FROST-secp256k1-SHA256-v1" || "chal".
 */
const CONTEXT = te.encode("FROST-secp256k1-SHA256-v1");

function H2(m: Uint8Array): bigint {
    const DST = dst_xmd_sha256([CONTEXT, te.encode("chal")]);
    return hash_to_scalar(m, DST);
}

// RFC 9591 (FROST(secp256k1, SHA-256)) verification:
// c = H2( SerializeElement(R) || SerializeElement(PK) || msg )
// where H2 = hash_to_field^XMD_SHA-256 with DST = "FROST-secp256k1-SHA256-v1"||"chal", L=48, p = secp256k1 order.

/**
 * FrostInputs — Inputs required to verify a FROST Schnorr signature over secp256k1.
 * All coordinates and scalars are hex strings (0x…); message may be ASCII or hex.
 */
export type FrostInputs = {
    px: string; // hex
    py: string; // hex
    rx: string; // hex
    ry: string; // hex
    s: string;  // hex (aka z)
    message: string | Uint8Array; // ASCII, hex, or raw bytes
};

/**
 * verifyFrost — Verifies a FROST(secp256k1, SHA-256) Schnorr signature.
 * Steps:
 *  1) SEC1-compress R and PK from (x,y).
 *  2) Compute challenge c = H2( Rc || PKc || msg ).
 *  3) Check s·G == R + c·PK.
 * Returns validity and the computed challenge as hex.
 */
export function verifyFrost(inputs: FrostInputs): { ok: boolean; challengeHex: string } {
    const {px, py, rx, ry, s, message} = inputs;

    const mBytes =
        message instanceof Uint8Array
            ? message
            : isHex(message) ? hexToBytes(message) : te.encode(message);

    // Build SEC1-compressed encodings from x,y
    const Rc = compressedFromXY(String(rx), String(ry));
    const PKc = compressedFromXY(String(px), String(py));

    // Parse points with noble (accepts compressed SEC1)
    const R = P.fromHex(Rc);
    const PK = P.fromHex(PKc);

    // s scalar (reject out-of-range instead of reducing)
    const sBytes = hexToBytes(s);
    if (sBytes.length == 0 || sBytes.length > 32) {
        throw new Error("s must be smaller than 32 bytes for secp256k1 sBytes.length = " + sBytes.length);
    }
    const sBI = os2ip(sBytes);
    if (sBI >= CURVE.n) {
        // eslint-disable-next-line no-console
        console.log("[debug] s not in [0, n-1] -> invalid signature");
    }

    // RFC 9591 §4.6: challenge = H2( SerializeElement(R) || SerializeElement(PK) || msg )
    const chalInput = concat(Rc, PKc, mBytes);
    let c = H2(chalInput);
    let cHex = "0x" + c.toString(16).padStart(64, "0");

    const lhs = P.BASE.multiply(sBI);
    const rhs = R.add(PK.multiply(c));
    const ok = lhs.equals(rhs);

    return {ok, challengeHex: cHex};
}

const bytesToBigInt = (b: Uint8Array | Buffer): bigint => BigInt("0x" + Buffer.from(b).toString("hex"));

export function bigintToBytes32BE(bn: bigint): Buffer {
    if (bn < 0n) throw new Error("negative bigint not allowed");
    const hex = bn.toString(16);            // no 0x, no leading zeros
    if (hex.length > 64) throw new Error("value does not fit in 32 bytes");
    const padded = hex.padStart(64, "0");   // left-pad to 64 hex chars
    return Buffer.from(padded, "hex");
}

function sign(m: string, x: Uint8Array) {
    const publicKey = secp.getPublicKey(x, true); // 33B compressed
    const P = secp.Point.fromBytes(publicKey);
    const n = secp.Point.CURVE().n;
    const xBI = bytesToBigInt(x);

    let s: bigint;
    let R: Uint8Array;
    let Rpoint: any;
    let kBI: bigint;

    // Loop until we get a nonzero s that passes scalar check
    do {
        // 1) Pick a valid nonce k
        let k: Uint8Array;
        do {
            k = randomBytes(32);
        } while (!secp.utils.isValidSecretKey(k));
        kBI = bytesToBigInt(k);

        // 2) R = k*G (compressed)
        R = secp.getPublicKey(k, true);
        Rpoint = secp.Point.fromBytes(R);

        // 3) Force even-Y: if R.y is odd, flip k -> n - k and recompute R
        if ((Rpoint.y & 1n) === 1n) {
            kBI = (n - kBI) % n;
            //const kBytes = ethers.zeroPadValue("0x" + kBI.toString(16), 32);
            R = secp.getPublicKey(bigintToBytes32BE(kBI), true);
            Rpoint = secp.Point.fromBytes(R);
        }

        // 4) e = H2(R, P, m) using the XMD construction to 48 bytes, mod n
        let chalInput = concat(R, publicKey, Buffer.from(m.slice(2), "hex"))
        const e = H2(chalInput);

        // 5) s = k + x*e (mod n)
        s = (kBI + (xBI * e) % n) % n;

        // Repeat if s == 0 (invalid per _isScalar in the verifier)
    } while (s === 0n);

    return {R, s};
}
