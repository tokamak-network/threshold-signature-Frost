import {expect} from "chai";
import {network} from "hardhat";

const {ethers} = await network.connect();

// @ts-ignore
import {secp256k1} from "@noble/curves/secp256k1";
import {keccak256, zeroPadValue} from "ethers";
import * as secp from "@noble/secp256k1";
import {randomBytes} from "crypto";
import {verifyFrost, sign, HALF_Q} from "../scripts/helper.js";

const {ProjectivePoint: P, CURVE} = secp256k1;
new TextEncoder();


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
