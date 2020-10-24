/*
Het is de bedoeling dat de peers de gedeelde sleutels berekenen met
respectievelijk de crypto_kx_client_session_keys en
crypto_kx_server_session_keys libsodium functies. Ze doen dit aan de hand
van hun eigen publieke en private sleutel en de publieke sleutel van de
tegenpartij. Beide functies geven 2 symmetrische sleutels terug, rx en tx,
de eerste om binnenkomende berichten te decrypteren, de laatste om uitgaande
 berichten te versleutelen. De rx van de client is de tx van de server
 en omgekeerd.
 */

const _nacl = require('libsodium-wrappers');
const Encryptor = require('./Encryptor.js');
const Decryptor = require('./Decryptor.js');
let message;

const secureSessionPeer = async(securePeer) => {
    await _nacl.ready;
    const nacl = _nacl;
    let sessionKeys;
    let keypair = nacl.crypto_kx_keypair();
    let publicKey = keypair.publicKey;
    let messagedecryptor;
    let messageencryptor;

    if (securePeer)
    {
        // tweede object werd aangemaakt : SERVER
        securePeer.connect(publicKey);
        sessionKeys = nacl.crypto_kx_server_session_keys(publicKey, keypair.privateKey, securePeer.publicKey);
        await setSessionKeys();
    }

    async function setSessionKeys(){
        messagedecryptor = await Decryptor(sessionKeys.sharedRx);
        messageencryptor = await Encryptor(sessionKeys.sharedTx);
    }

    function connector(key){
        sessionKeys = nacl.crypto_kx_client_session_keys(publicKey, keypair.privateKey, key);
        setSessionKeys();
    }

    function decryptor(ciphertext, nonce) {
          return messagedecryptor.decrypt(ciphertext, nonce);
    }

    function encryptor(msg) {
     return messageencryptor.encrypt(msg);
    }

    return Object.freeze({
        publicKey,
        decrypt: (ciphertext, nonce) => decryptor(ciphertext, nonce),
        encrypt:(msg) => encryptor(msg),
        send: (msg) => {message = encryptor(msg)},
        receive: () => { return decryptor(message.ciphertext, message.nonce)},
        connect: (key) => connector(key)
    });
};
module.exports = secureSessionPeer;