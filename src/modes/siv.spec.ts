import { hexToBytes } from "@noble/ciphers/utils.js";
import { describe, test, expect } from "bun:test";
import { siv_decrypt, siv_encrypt } from "./siv.js";
import { getEncrypter } from "./_test_utils.js";

const getSivEncrypters = (key: string) => {
    const k = hexToBytes(key);
    const h = k.length / 2;

    return [getEncrypter(k.subarray(0,h)), getEncrypter(k.subarray(h))];
}

describe("SIV", () => {
    test("128 bits", () => {
        const [K1, K2] = getSivEncrypters("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        const aad = hexToBytes("101112131415161718191a1b1c1d1e1f2021222324252627");
        const pt = hexToBytes("112233445566778899aabbccddee");
        const ct = hexToBytes("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c");
        
        expect(siv_encrypt(K1, K2, 16, pt, [aad])).toStrictEqual(ct);
        expect(siv_decrypt(K1, K2, 16, ct, [aad])).toStrictEqual(pt);
    });

    test("128 bits #2", () => {
        const [K1, K2] = getSivEncrypters("7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f");
        const aad1 = hexToBytes('00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100');
        const aad2 = hexToBytes('102030405060708090a0');
        const nonce = hexToBytes('09f911029d74e35bd84156c5635688c0');
        const pt = new TextEncoder().encode("this is some plaintext to encrypt using SIV-AES");
        const ct = hexToBytes("7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d");
        
        expect(siv_encrypt(K1, K2, 16, pt, [aad1, aad2, nonce])).toStrictEqual(ct);
        expect(siv_decrypt(K1, K2, 16, ct, [aad1, aad2, nonce])).toStrictEqual(pt);
    });
});