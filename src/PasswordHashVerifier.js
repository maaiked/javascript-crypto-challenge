/*
We use Argon2 as the password hashing algorithm -
this is default in the current version of libsodium.
crypto_pwhash_str generates a random salt for each invocation,
concatenates the salt and password and hashes the resulting
string. Argon2 uses a configurable number of hash
iterations (the opslimit parameter) and memory (memlimit)
to make verification respectively more CPU- and RAM-intensive.
The output of crypto_pwhash_str includes the parameters
and salt. These need therefore not be specified when verifying
a password against its hash.
 */

const _nacl = require('libsodium-wrappers');

module.exports = async () => {
    await _nacl.ready;
    const nacl = _nacl;

    return Object.freeze({
        verify: (hashedPw, pw) => nacl.crypto_pwhash_str_verify(hashedPw, pw)
    })

};