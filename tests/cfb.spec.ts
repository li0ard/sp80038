import { hexToBytes } from "@noble/ciphers/utils.js";
import { describe, test, expect } from "bun:test";
import { cfb_decrypt, cfb_encrypt } from "../src/index.js";
import { getEncrypter, IV, KEY128, KEY192, KEY256, PLAINTEXT } from "./_test_utils.js";

describe("CFB-8", () => {
    test("128 bits", () => {
        const ciphertext = hexToBytes(
            "3b79424c9c0dd436bace9e0ed4586a4f" +
            "32b9"
        );

        expect(cfb_encrypt(getEncrypter(KEY128), 16, PLAINTEXT, IV, 1).subarray(0,18)).toStrictEqual(ciphertext);
        expect(cfb_decrypt(getEncrypter(KEY128), 16, ciphertext, IV, 1)).toStrictEqual(PLAINTEXT.slice(0,18));
    });

    test("192 bits", () => {
        const ciphertext = hexToBytes(
            "cda2521ef0a905ca44cd057cbf0d47a0" +
            "678a"
        );

        expect(cfb_encrypt(getEncrypter(KEY192), 16, PLAINTEXT, IV, 1).subarray(0,18)).toStrictEqual(ciphertext);
        expect(cfb_decrypt(getEncrypter(KEY192), 16, ciphertext, IV, 1)).toStrictEqual(PLAINTEXT.slice(0,18));
    });

    test("256 bits", () => {
        const ciphertext = hexToBytes(
            "dc1f1a8520a64db55fcc8ac554844e88" +
            "9700"
        );

        expect(cfb_encrypt(getEncrypter(KEY256), 16, PLAINTEXT, IV, 1).subarray(0,18)).toStrictEqual(ciphertext);
        expect(cfb_decrypt(getEncrypter(KEY256), 16, ciphertext, IV, 1)).toStrictEqual(PLAINTEXT.slice(0,18));
    });
});

describe("CFB-128", () => {
    test("128 bits", () => {
        const ciphertext = hexToBytes(
            "3b3fd92eb72dad20333449f8e83cfb4a" +
            "c8a64537a0b3a93fcde3cdad9f1ce58b" +
            "26751f67a3cbb140b1808cf187a4f4df" +
            "c04b05357c5d1c0eeac4c66f9ff7f2e6"
        );

        expect(cfb_encrypt(getEncrypter(KEY128), 16, PLAINTEXT, IV)).toStrictEqual(ciphertext);
        expect(cfb_decrypt(getEncrypter(KEY128), 16, ciphertext, IV)).toStrictEqual(PLAINTEXT);
    });

    test("192 bits", () => {
        const ciphertext = hexToBytes(
            "cdc80d6fddf18cab34c25909c99a4174" +
            "67ce7f7f81173621961a2b70171d3d7a" +
            "2e1e8a1dd59b88b1c8e60fed1efac4c9" +
            "c05f9f9ca9834fa042ae8fba584b09ff"
        );

        expect(cfb_encrypt(getEncrypter(KEY192), 16, PLAINTEXT, IV)).toStrictEqual(ciphertext);
        expect(cfb_decrypt(getEncrypter(KEY192), 16, ciphertext, IV)).toStrictEqual(PLAINTEXT);
    });

    test("256 bits", () => {
        const ciphertext = hexToBytes(
            "dc7e84bfda79164b7ecd8486985d3860" +
            "39ffed143b28b1c832113c6331e5407b" +
            "df10132415e54b92a13ed0a8267ae2f9" +
            "75a385741ab9cef82031623d55b1e471"
        );

        expect(cfb_encrypt(getEncrypter(KEY256), 16, PLAINTEXT, IV)).toStrictEqual(ciphertext);
        expect(cfb_decrypt(getEncrypter(KEY256), 16, ciphertext, IV)).toStrictEqual(PLAINTEXT);
    });
});