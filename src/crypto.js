import crypto from 'crypto'
import BigInteger from 'big-integer'
import nacl from 'tweetnacl'
import util from 'tweetnacl-util'
nacl.util = util

import { converters } from 'nxt-utils'
import curve25519 from './curve25519'

export const byteArrayToHashByteArray = (byteArray) => {
  const hashBytes = crypto.createHash('sha256')
    .update(new Buffer(byteArray))
    .digest('hex')
  return converters.hexStringToByteArray(hashBytes)
}

export const areByteArraysEqual = (bytes1, bytes2) => {
  if (bytes1.length !== bytes2.length) {
    return false
  }

  for (var i = 0; i < bytes1.length; ++i) {
    if (bytes1[i] !== bytes2[i]) {
      return false
    }
  }

  return true
}

export const verifyBytes = (signature, message, publicKey) => {
  let signatureBytes = signature
  let messageBytes = message
  let publicKeyBytes = publicKey
  let v = signatureBytes.slice(0, 32)
  let h = signatureBytes.slice(32)
  let y = curve25519.verify(v, h, publicKeyBytes)
  let m = crypto.createHash('sha256').update(new Buffer(messageBytes)).digest('hex')
  let h2 = crypto.createHash('sha256')
    .update(new Buffer(converters.hexStringToByteArray(m)))
    .update(new Buffer(y))
    .digest('hex')

  return areByteArraysEqual(h, converters.hexStringToByteArray(h2))
}

export const parseToken = (tokenString, website) => {
  let websiteBytes = converters.stringToByteArray(website)
  let tokenBytes = []
  let i = 0
  let j = 0

  for (; i < tokenString.length; i += 8, j += 5) {
    let number = BigInteger(tokenString.substring(i, i + 8), 32)
    let part = converters.hexStringToByteArray(number.toString(16))
    tokenBytes[j] = part[4]
    tokenBytes[j + 1] = part[3]
    tokenBytes[j + 2] = part[2]
    tokenBytes[j + 3] = part[1]
    tokenBytes[j + 4] = part[0]
  }

  if (i !== 160) {
    throw Error('tokenString parsed to invalid size')
  }

  let publicKey = tokenBytes.slice(0, 32)
  let timebytes = [tokenBytes[32], tokenBytes[33], tokenBytes[34], tokenBytes[35]]

  let timestamp = converters.byteArrayToIntVal(timebytes)
  let signature = tokenBytes.slice(36, 100)
  let data = websiteBytes.concat(tokenBytes.slice(0, 36))

  let isValid = verifyBytes(signature, data, publicKey)
  publicKey = converters.byteArrayToHexString(publicKey)

  return {
    isValid,
    timestamp,
    publicKey
  }
}

export const getPublicKey = (secretPhrase) => {
  const secretPhraseBytes = converters.stringToByteArray(secretPhrase)
  const hashBytes = byteArrayToHashByteArray(secretPhraseBytes)

  return converters.byteArrayToHexString(curve25519.keygen(hashBytes).p);
}

export const getAccountId = (publicKey) => {
  const publicKeyBytes = converters.hexStringToByteArray(publicKey)
  const hashBytes = byteArrayToHashByteArray(publicKeyBytes)
  const account = converters.byteArrayToHexString(hashBytes)
  const accountSlice = converters.hexStringToByteArray(account).slice(0, 8)
  const accountId = converters.byteArrayToBigInteger(accountSlice).toString()

  return accountId
}

export const generateSecretPhrase = () => {
  const bytes = nacl.randomBytes(128)
  return crypto.createHash('sha512').update(bytes).digest('hex')
}

export const createKeyBytes = (key) => {
  // hash the key so we have 32 bytes key
  const hash = crypto.createHash('sha256').update(key).digest('base64')
  // convert key into bytes
  return nacl.util.decodeBase64(hash)
}

/**
 * Encrypt the message with the given key
 * @param  {string} message
 * @param  {string} key
 * @return {object} object
 */
export const encrypt = (message, key) => {
  // convert message to bytes
  const messageBytes = nacl.util.decodeUTF8(message)
  // generate 24 byte nonce
  const nonceBytes = nacl.randomBytes(24)
  // generate key bytes
  const keyBytes = createKeyBytes(key)
  // encrypt
  const encryptedBytes = nacl.secretbox(messageBytes, nonceBytes, keyBytes)

  return {
    nonce: nacl.util.encodeBase64(nonceBytes),
    message: nacl.util.encodeBase64(encryptedBytes)
  }
}

/**
 * Decrypt the given message object and return the UTF8 string
 * @param  {object} encrypted
 * @param  {string} key
 * @return {string} decrypted message
 */
export const decrypt = (encrypted, key) => {
  if (typeof encrypted === 'string') {
    try {
      encrypted = JSON.parse(encrypted)
    } catch (e) {
      return null
    }
  }

  if (!encrypted || !encrypted.message) {
    return null
  }

  // convert message to bytes
  const messageBytes = nacl.util.decodeBase64(encrypted.message)
  // convert key into bytes
  const keyBytes = createKeyBytes(key)
  // convert nonce to bytes
  const nonceBytes = nacl.util.decodeBase64(encrypted.nonce)
  // decrypt
  const decryptedBytes = nacl.secretbox.open(messageBytes, nonceBytes, keyBytes)
  // return encoded UTF8 string
  return nacl.util.encodeUTF8(decryptedBytes)
}

export const sha256 = (string) => {
  return crypto.createHash('sha256').update(string).digest('hex')
}

export default {
  verifyBytes,
  parseToken,
  getPublicKey,
  getAccountId,
  generateSecretPhrase,
  encrypt,
  decrypt,
  sha256
}
