'use strict'
const nacl = require('libsodium-wrappers')

const SecureSessionPeer = require('../src/SecureSessionPeer')

describe('SecureSessionPeer', () => {
  let peer
  beforeAll(async () => {
    peer = await SecureSessionPeer()
  })
  xit('can be instantiated', () => {
    expect(peer).toBeDefined()
  })
  describe('has a public key', () => {
    xit('that can be retrieved', () => {
      expect(peer.publicKey).toBeDefined()
    })
    xit('that cannot be changed', () => {
      try {
        peer.publicKey = '42'
        fail()
      } catch(e) {
      }
    })
  })
  describe('presumably hides a private key somewhere', () => {
    xit('but that is being kept secret', () => {
      expect(peer.privateKey).not.toBeDefined()
    })
    xit('and cannot be changed', () => {
      try {
        peer.privateKey = '42'
        fail()
      } catch(e) {
      }
    })
  })
  describe('connects to another SecureSessionPeer', () => {
    let otherPeer
    beforeAll(async () => {
      otherPeer = await SecureSessionPeer(peer)
    })
    xit('resulting in 2 distinct peers with different public keys', () => {
      expect(peer).not.toEqual(otherPeer)
      expect(peer.publicKey).not.toEqual(otherPeer.publicKey)
    })
    describe('which can encrypt messages', () => {
      let msg, peerCiphertext, otherPeerCiphertext, peerNonce, otherPeerNonce
      beforeEach(async () => {
        await nacl.ready
        msg = nacl.randombytes_buf(1024)
        let res = peer.encrypt(msg)
        peerCiphertext = res.ciphertext
        peerNonce = res.nonce
        res = otherPeer.encrypt(msg)
        otherPeerCiphertext = res.ciphertext
        otherPeerNonce = res.nonce
      })
      xit('returning a ciphertext and a nonce', () => {
        expect(peerCiphertext).toBeDefined()
        expect(peerNonce).toBeDefined()
        expect(otherPeerCiphertext).toBeDefined()
        expect(otherPeerNonce).toBeDefined()
      })
      xit('that can be decrypted messages by the other peer', () => {
        expect(otherPeer.decrypt(peerCiphertext, peerNonce)).toEqual(msg)
      })
      xit('that cannot be decrypted with the public key', () => {
        try {
          nacl.crypto_secretbox_open_easy(peerCiphertext, peerNonce, peer.publicKey)
          fail()
        } catch (e) {}
      })
      xit('that are integrity protected', () => {
        const {ciphertext, nonce} = peer.encrypt(msg)
        const tamperIdx = nacl.randombytes_uniform(ciphertext.length)
        ciphertext[tamperIdx] = (ciphertext[tamperIdx] + 1) % 256 // each el is 8 bits
        try {
          otherPeer.decrypt(ciphertext, nonce)
          fail()
        } catch(e) {
        }
      })
    })
    xit('that exchange messages', async () => {
      await nacl.ready
      const peerMsg = nacl.randombytes_buf(1024)
      const otherPeerMsg = nacl.randombytes_buf(1024)
      peer.send(peerMsg)
      let received = otherPeer.receive()
      expect(received).toEqual(peerMsg)
      otherPeer.send(otherPeerMsg)
      received = peer.receive()
      expect(received).toEqual(otherPeerMsg)
    })
  })
})
