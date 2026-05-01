import { hexToBytes } from "@noble/ciphers/utils.js";
import { describe, test, expect } from "bun:test";
import { ctr } from "../src/index.js";
import { getEncrypter, IV2, KEY128, KEY192, KEY256, PLAINTEXT } from "./_test_utils.js";

describe("CTR", () => {
    test("128 bits", () => {
        const encrypter = getEncrypter(KEY128);
        const ciphertext = hexToBytes(
            "874d6191b620e3261bef6864990db6ce" +
            "9806f66b7970fdff8617187bb9fffdff" +
            "5ae4df3edbd5d35e5b4f09020db03eab" +
            "1e031dda2fbe03d1792170a0f3009cee"
        );
        
        expect(ctr(encrypter, 16, PLAINTEXT, IV2)).toStrictEqual(ciphertext);
        expect(ctr(encrypter, 16, ciphertext, IV2)).toStrictEqual(PLAINTEXT);
    });

    test("192 bits", () => {
        const encrypter = getEncrypter(KEY192);
        const ciphertext = hexToBytes(
            "1abc932417521ca24f2b0459fe7e6e0b" +
            "090339ec0aa6faefd5ccc2c6f4ce8e94" +
            "1e36b26bd1ebc670d1bd1d665620abf7" +
            "4f78a7f6d29809585a97daec58c6b050"
        );

        expect(ctr(encrypter, 16, PLAINTEXT, IV2)).toStrictEqual(ciphertext);
        expect(ctr(encrypter, 16, ciphertext, IV2)).toStrictEqual(PLAINTEXT);
    });

    test("256 bits", () => {
        const encrypter = getEncrypter(KEY256);
        const ciphertext = hexToBytes(
            "601ec313775789a5b7a7f504bbf3d228" +
            "f443e3ca4d62b59aca84e990cacaf5c5" +
            "2b0930daa23de94ce87017ba2d84988d" +
            "dfc9c58db67aada613c2dd08457941a6"
        );

        expect(ctr(encrypter, 16, PLAINTEXT, IV2)).toStrictEqual(ciphertext);
        expect(ctr(encrypter, 16, ciphertext, IV2)).toStrictEqual(PLAINTEXT);
    });
});