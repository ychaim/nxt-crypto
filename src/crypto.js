import crypto from 'crypto'
import BigInteger from 'big-integer'
import nacl from 'tweetnacl'
import util from 'tweetnacl-util'
nacl.util = util

import {
  byteArrayToIntVal,
  byteArrayToHexString,
  byteArrayToBigInteger,
  stringToByteArray,
  hexStringToByteArray,
  stringToHexString
} from './converters'
import curve25519 from './curve25519'
import nxtAddress from './nxtAddress'

export const byteArrayToHashByteArray = (byteArray, byteArray2) => {
  const hashBytes = crypto.createHash('sha256')
    .update(new Buffer(byteArray))

  if (byteArray2) {
    hashBytes.update(new Buffer(byteArray2))
  }

  return hexStringToByteArray(hashBytes.digest('hex'))
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

const verifyBytes = (signature, message, publicKey) => {
  let signatureBytes = signature
  let messageBytes = message
  let publicKeyBytes = publicKey
  let v = signatureBytes.slice(0, 32)
  let h = signatureBytes.slice(32)
  let y = curve25519.verify(v, h, publicKeyBytes)
  let m = crypto.createHash('sha256').update(new Buffer(messageBytes)).digest('hex')
  let h2 = crypto.createHash('sha256')
    .update(new Buffer(hexStringToByteArray(m)))
    .update(new Buffer(y))
    .digest('hex')

  return areByteArraysEqual(h, hexStringToByteArray(h2))
}

export const parseToken = (tokenString, dataString) => {
  let dataBytes = stringToByteArray(dataString)
  let tokenBytes = []
  let i = 0
  let j = 0

  for (; i < tokenString.length; i += 8, j += 5) {
    let number = BigInteger(tokenString.substring(i, i + 8), 32)
    let part = hexStringToByteArray(number.toString(16))
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

  let timestamp = byteArrayToIntVal(timebytes)
  let signature = tokenBytes.slice(36, 100)
  let data = dataBytes.concat(tokenBytes.slice(0, 36))

  let isValid = verifyBytes(signature, data, publicKey)
  publicKey = byteArrayToHexString(publicKey)

  return {
    isValid,
    timestamp,
    publicKey
  }
}

export const getPublicKey = (secretPhrase) => {
  const secretPhraseBytes = stringToByteArray(secretPhrase)
  const hashBytes = byteArrayToHashByteArray(secretPhraseBytes)

  return byteArrayToHexString(curve25519.keygen(hashBytes).p);
}

export function getAccountRSFromSecretPhrase(secretphrase, prefix = 'NXT') {
  const publicKey = getPublicKey(secretphrase);

  return getAccountRS(publicKey, prefix);
}

export const getAccountId = (publicKey) => {
  const publicKeyBytes = hexStringToByteArray(publicKey)
  const hashBytes = byteArrayToHashByteArray(publicKeyBytes)
  const account = byteArrayToHexString(hashBytes)
  const accountSlice = hexStringToByteArray(account).slice(0, 8)
  const accountId = byteArrayToBigInteger(accountSlice).toString()

  return accountId
}

export const getAccountRS = (publicKey, prefix = 'NXT') => {
  const accountId = getAccountId(publicKey)
  const accountRS = new nxtAddress(prefix)
  accountRS.set(accountId)
  return accountRS.toString()
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

/**
 * Sign transaction bytes
 * @param  {string} message
 * @param  {string} secretphrase
 * @return {string} signed transaction bytes
 */
export function signBytes(message, secretphrase) {
  secretphrase = stringToHexString(secretphrase)
  const messageBytes = hexStringToByteArray(message)
  const secretphraseBytes = hexStringToByteArray(secretphrase)

  const digest = byteArrayToHashByteArray(secretphraseBytes)
  const s = curve25519.keygen(digest).s
  const m = byteArrayToHashByteArray(messageBytes)
  const x = byteArrayToHashByteArray(m, s)
  const y = curve25519.keygen(x).p
  const h = byteArrayToHashByteArray(m, y)
  const v = curve25519.sign(h, x, s)
  return byteArrayToHexString(v.concat(h))
}

export default {
  parseToken,
  getPublicKey,
  getAccountId,
  getAccountRS,
  getAccountRSFromSecretPhrase,
  generateSecretPhrase,
  encrypt,
  decrypt,
  sha256,
  signBytes
}
