const nacl = require('libsodium-wrappers');

module.exports = async () => {
    await nacl.ready;
    let key = nacl.crypto_secretbox_keygen();
    let nonce = nacl.randombytes_buf(nacl.crypto_secretbox_NONCEBYTES);

    return Object.freeze({
        encrypt: (message) => {
            return nacl.crypto_secretbox_easy(message, nonce, key);
        }
    })
};