const _nacl = require('libsodium-wrappers');

module.exports = async () => {

    await _nacl.ready;
    const nacl = _nacl;
    let key = nacl.crypto_secretbox_keygen();
    let nonce = nacl.randombytes_buf(nacl.crypto_secretbox_NONCEBYTES);

    return Object.freeze({
        encrypt: (message) => {
            return nacl.crypto_secretbox_easy(message, nonce, key);
        }
    })
};