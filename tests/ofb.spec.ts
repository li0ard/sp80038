import { hexToBytes } from "@noble/ciphers/utils.js";
import { describe, test, expect } from "bun:test";
import { ofb } from "../src/index.js";
import { getEncrypter, IV, KEY128, KEY192, KEY256, PLAINTEXT } from "./_test_utils.js";

describe("OFB", () => {
    test("128 bits", () => {
        const encrypter = getEncrypter(KEY128);
        const ciphertext = hexToBytes(
            "3b3fd92eb72dad20333449f8e83cfb4a" +
            "7789508d16918f03f53c52dac54ed825" +
            "9740051e9c5fecf64344f7a82260edcc" +
            "304c6528f659c77866a510d9c1d6ae5e"
        );
        
        expect(ofb(encrypter, 16, PLAINTEXT, IV)).toStrictEqual(ciphertext);
        expect(ofb(encrypter, 16, ciphertext, IV)).toStrictEqual(PLAINTEXT);
    });

    test("192 bits", () => {
        const encrypter = getEncrypter(KEY192);
        const ciphertext = hexToBytes(
            "cdc80d6fddf18cab34c25909c99a4174" +
            "fcc28b8d4c63837c09e81700c1100401" +
            "8d9a9aeac0f6596f559c6d4daf59a5f2" +
            "6d9f200857ca6c3e9cac524bd9acc92a"
        );

        expect(ofb(encrypter, 16, PLAINTEXT, IV)).toStrictEqual(ciphertext);
        expect(ofb(encrypter, 16, ciphertext, IV)).toStrictEqual(PLAINTEXT);
    });

    test("256 bits", () => {
        const encrypter = getEncrypter(KEY256);
        const ciphertext = hexToBytes(
            "dc7e84bfda79164b7ecd8486985d3860" +
            "4febdc6740d20b3ac88f6ad82a4fb08d" +
            "71ab47a086e86eedf39d1c5bba97c408" +
            "0126141d67f37be8538f5a8be740e484"
        );

        expect(ofb(encrypter, 16, PLAINTEXT, IV)).toStrictEqual(ciphertext);
        expect(ofb(encrypter, 16, ciphertext, IV)).toStrictEqual(PLAINTEXT);
    });
});