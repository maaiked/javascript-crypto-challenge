/*
We use public-key signatures. They are based on asymmetric key pairs:
one of the keys is public, the other private. The public key is sometimes also
called the verifying key. The secret, or private, key is also called the signing
key.
 */

const _nacl = require('libsodium-wrappers');

module.exports = async () => {
    await _nacl.ready;
    const nacl = _nacl;

    const key = nacl.crypto_sign_keypair();

    return Object.freeze({
        verifyingKey: key.publicKey,
        sign: (msg) => nacl.crypto_sign(msg, key.privateKey)
    })
};