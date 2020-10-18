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
let client = true;
let clientKeys;
let serverKeys;
let message;

const secureSessionPeer = async(securePeer = null) => {
    await _nacl.ready;
    const nacl = _nacl;
    let publicKey = null;

    clientKeys = nacl.crypto_kx_keypair();
    serverKeys = nacl.crypto_kx_keypair();
    let clientsessionKey = nacl.crypto_kx_client_session_keys(clientKeys.publicKey, clientKeys.privateKey, serverKeys.publicKey);
    let serversessionKey = nacl.crypto_kx_client_session_keys(serverKeys.publicKey, serverKeys.privateKey, clientKeys.publicKey);

    if (client) {
        publicKey = clientKeys.publicKey;
    }
    else {
        publicKey = serverKeys.publicKey;
    }

    let clientdecryptor = await Decryptor(clientsessionKey.sharedRx);
    let serverdecryptor = await Decryptor(serversessionKey.sharedRx);
    let clientencryptor = await Encryptor(clientsessionKey.sharedTx);
    let serverencryptor = await Encryptor(serversessionKey.sharedTx);

    function decryptor(ciphertext, nonce) {
        if (!client) { return serverdecryptor.decrypt(ciphertext, nonce);
        } else return  clientdecryptor.decrypt(ciphertext, nonce);
    }
    function encryptor(msg) {
        if (!client) { return serverencryptor.encrypt(msg)
        } else return clientencryptor.encrypt(msg);
    }

    return Object.freeze({
        publicKey: publicKey,
        decrypt: (ciphertext, nonce) => decryptor(ciphertext, nonce),
        encrypt:(msg) => encryptor(msg),
        send: (msg) => {message = encryptor(msg)},
        receive: () => { return decryptor(message.ciphertext, message.nonce)},
    });
};
module.exports = secureSessionPeer;