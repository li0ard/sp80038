import { hexToBytes } from "@noble/ciphers/utils.js";
import { describe, test, expect } from "bun:test";
import { cbc_decrypt, cbc_encrypt } from "../src/";
import { getDecrypter, getEncrypter, IV, KEY128, KEY192, KEY256, PLAINTEXT } from "./_test_utils.js";

describe("CBC", () => {
    test("128 bits", () => {
        const ciphertext = hexToBytes(
            "7649abac8119b246cee98e9b12e9197d" +
            "5086cb9b507219ee95db113a917678b2" +
            "73bed6b8e3c1743b7116e69e22229516" +
            "3ff1caa1681fac09120eca307586e1a7"
        );

        expect(cbc_encrypt(getEncrypter(KEY128), 16, PLAINTEXT, IV)).toStrictEqual(ciphertext);
        expect(cbc_decrypt(getDecrypter(KEY128), 16, ciphertext, IV)).toStrictEqual(PLAINTEXT);
    });

    test("192 bits", () => {
        const ciphertext = hexToBytes(
            "4f021db243bc633d7178183a9fa071e8" +
            "b4d9ada9ad7dedf4e5e738763f69145a" +
            "571b242012fb7ae07fa9baac3df102e0" +
            "08b0e27988598881d920a9e64f5615cd"
        );

        expect(cbc_encrypt(getEncrypter(KEY192), 16, PLAINTEXT, IV)).toStrictEqual(ciphertext);
        expect(cbc_decrypt(getDecrypter(KEY192), 16, ciphertext, IV)).toStrictEqual(PLAINTEXT);
    });

    test("256 bits", () => {
        const ciphertext = hexToBytes(
            "f58c4c04d6e5f1ba779eabfb5f7bfbd6" +
            "9cfc4e967edb808d679f777bc6702c7d" +
            "39f23369a9d9bacfa530e26304231461" +
            "b2eb05e2c39be9fcda6c19078c6a9d1b"
        );

        expect(cbc_encrypt(getEncrypter(KEY256), 16, PLAINTEXT, IV)).toStrictEqual(ciphertext);
        expect(cbc_decrypt(getDecrypter(KEY256), 16, ciphertext, IV)).toStrictEqual(PLAINTEXT);
    });
});