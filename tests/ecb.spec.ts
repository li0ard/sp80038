import { hexToBytes } from "@noble/ciphers/utils.js";
import { describe, test, expect } from "bun:test";
import { ecb } from "../src/";
import { getDecrypter, getEncrypter, KEY128, KEY192, KEY256, PLAINTEXT } from "./_test_utils.js";
describe("ECB", () => {
    test("128 bits", () => {
        const ciphertext = hexToBytes(
            "3ad77bb40d7a3660a89ecaf32466ef97" +
            "f5d3d58503b9699de785895a96fdbaaf" +
            "43b1cd7f598ece23881b00e3ed030688" +
            "7b0c785e27e8ad3f8223207104725dd4"
        );

        expect(ecb(getEncrypter(KEY128), 16, PLAINTEXT)).toStrictEqual(ciphertext);
        expect(ecb(getDecrypter(KEY128), 16, ciphertext)).toStrictEqual(PLAINTEXT);
    });

    test("192 bits", () => {
        const ciphertext = hexToBytes(
            "bd334f1d6e45f25ff712a214571fa5cc" +
            "974104846d0ad3ad7734ecb3ecee4eef" +
            "ef7afd2270e2e60adce0ba2face6444e" +
            "9a4b41ba738d6c72fb16691603c18e0e"
        );

        expect(ecb(getEncrypter(KEY192), 16, PLAINTEXT)).toStrictEqual(ciphertext);
        expect(ecb(getDecrypter(KEY192), 16, ciphertext)).toStrictEqual(PLAINTEXT);
    });

    test("256 bits", () => {
        const ciphertext = hexToBytes(
            "f3eed1bdb5d2a03c064b5a7e3db181f8" +
            "591ccb10d410ed26dc5ba74a31362870" +
            "b6ed21b99ca6f4f9f153e7b1beafed1d" +
            "23304b7a39f9f3ff067d8d8f9e24ecc7"
        );

        expect(ecb(getEncrypter(KEY256), 16, PLAINTEXT)).toStrictEqual(ciphertext);
        expect(ecb(getDecrypter(KEY256), 16, ciphertext)).toStrictEqual(PLAINTEXT);
    });
});