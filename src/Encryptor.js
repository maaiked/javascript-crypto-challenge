const _nacl = require('libsodium-wrappers');

module.exports = async (key) => {

    await _nacl.ready;
    const nacl = _nacl;
    let nonce = nacl.randombytes_buf(nacl.crypto_secretbox_NONCEBYTES);

    return Object.freeze({
        encrypt: (message) => {
            return {
                ciphertext: nacl.crypto_secretbox_easy(message, nonce, key),
                nonce: nonce
                 }}
    })
};