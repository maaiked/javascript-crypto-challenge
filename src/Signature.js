const nacl = require('libsodium-wrappers');

module.exports = async () => {
    await nacl.ready;

    const key = nacl.crypto_sign_keypair();

    return Object.freeze({
        verifyingKey: key.publicKey,
        sign: (msg) => nacl.crypto_sign(msg, key.privateKey)
    })
};