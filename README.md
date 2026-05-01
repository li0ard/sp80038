<p align="center">
    <b>@li0ard/sp80038</b><br>
    <b>Cipher modes according to NIST SP 800-38 in pure TypeScript</b>
    <br>
    <a href="https://li0ard.is-cool.dev/sp80038">docs</a>
    <br><br>
    <a href="https://github.com/li0ard/sp80038/blob/main/LICENSE"><img src="https://img.shields.io/github/license/li0ard/sp80038" /></a>
    <br>
    <a href="https://npmjs.com/package/@li0ard/sp80038"><img src="https://img.shields.io/npm/v/@li0ard/sp80038" /></a>
    <a href="https://jsr.io/@li0ard/sp80038"><img src="https://jsr.io/badges/@li0ard/sp80038" /></a>
    <br>
    <hr>
</p>

> [!WARNING]
> This module contains only wrappers for encryption modes without reference to a specific cipher

## Installation

```bash
# from NPM
npm i @li0ard/sp80038

# from JSR
bunx jsr i @li0ard/sp80038
```

## Supported modes
- [x] Electronic Codebook (ECB)
- [x] Cipher Block Chaining (CBC)
- [x] Cipher Feedback (CFB)
- [x] Counter (CTR)
- [x] Output Feedback (OFB)
- [x] CMAC

## Features
- Provides simple and modern API
- Most of the APIs are strictly typed
- Fully complies with [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final) and [NIST SP 800-38B](https://csrc.nist.gov/pubs/sp/800/38/b/upd1/final) standards
- Supports Bun, Node.js, Deno, Browsers