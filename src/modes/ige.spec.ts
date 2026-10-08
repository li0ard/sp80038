import { hexToBytes } from "@noble/ciphers/utils.js";
import { describe, test, expect } from "bun:test";
import { ige_decrypt, ige_encrypt } from "./ige.js";
import { getDecrypter, getEncrypter, IV as IV_ } from "./_test_utils.js";

const PLAINTEXT = new Uint8Array(32);
const PLAINTEXT2 = hexToBytes("99706487A1CDE613BC6DE0B6F24B1C7AA448C8B9C3403E3467A8CAD89340F53B");
const IV = hexToBytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

const KEY = new TextEncoder().encode("This is an imple");
const IV2 = new TextEncoder().encode("mentation of IGE mode for OpenSS");

describe("IGE", () => {
    test("128 bits", () => {
        const ciphertext = hexToBytes(
            "1A8519A6557BE652E9DA8E43DA4EF445" +
            "3CF456B4CA488AA383C79C98B34797CB"
        );

        expect(ige_encrypt(getEncrypter(IV_), 16, PLAINTEXT, IV)).toStrictEqual(ciphertext);
        expect(ige_decrypt(getDecrypter(IV_), 16, ciphertext, IV)).toStrictEqual(PLAINTEXT);
    });

    test("128 bits #2", () => {
        const ciphertext = hexToBytes(
            "4C2E204C6574277320686F7065204265" +
            "6E20676F74206974207269676874210A"
        );

        expect(ige_encrypt(getEncrypter(KEY), 16, PLAINTEXT2, IV2)).toStrictEqual(ciphertext);
        expect(ige_decrypt(getDecrypter(KEY), 16, ciphertext, IV2)).toStrictEqual(PLAINTEXT2);
    });
});