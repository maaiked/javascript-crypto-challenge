/*
For encrypting and decrypting data, we use symmetric cryptography, also called
secret-key cryptography. This means that the same key is used for encrypting and
decrypting. Since an adversary should not be able to detect that the same plaintext
message is sent several times, each message is encrypted with a unique nonce.
We use authenticated encryption which allows the receiver to verify the
integrity of the ciphertext. Libsodium does this transparently - if the ciphertext
has been tampered with, the decryption function fails.
 */

const _nacl = require('libsodium-wrappers');

module.exports = async (key) => {
    await _nacl.ready;
    const nacl = _nacl;

    if (!key) {
        throw 'no key'
    }

    return Object.freeze({
        decrypt: (ciphertext, nonce) => nacl.crypto_secretbox_open_easy(ciphertext, nonce, key)
    })
};