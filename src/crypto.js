import crypto from 'crypto'
import nacl from 'tweetnacl'
import BigInteger from 'big-integer'

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

export default {
  verifyBytes,
  parseToken,
  getPublicKey,
  getAccountId,
  generateSecretPhrase
}
