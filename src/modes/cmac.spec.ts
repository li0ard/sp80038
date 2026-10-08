import { hexToBytes } from "@noble/ciphers/utils.js";
import { describe, test, expect } from "bun:test";
import { cmac } from "./cmac.js";
import { ENCRYPTER128, ENCRYPTER192, ENCRYPTER256, PLAINTEXT } from "./_test_utils.js";

describe("CMAC", () => {
    test("128 bits", () => {
        const ciphertext = hexToBytes("51F0BEBF7E3B9D92FC49741779363CFE");
        expect(cmac(ENCRYPTER128, 16, PLAINTEXT)).toStrictEqual(ciphertext);
    });

    test("192 bits", () => {
        const ciphertext = hexToBytes("A1D5DF0EED790F794D77589659F39A11");
        expect(cmac(ENCRYPTER192, 16, PLAINTEXT)).toStrictEqual(ciphertext);
    });

    test("256 bits", () => {
        const ciphertext = hexToBytes("E1992190549F6ED5696A2C056C315410");
        expect(cmac(ENCRYPTER256, 16, PLAINTEXT)).toStrictEqual(ciphertext);
    });
})