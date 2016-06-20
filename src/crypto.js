import crypto from 'crypto'
import BigInteger from 'big-integer'
import { Converters } from 'nxt-utils'
import curve25519 from './curve25519'

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
    .update(new Buffer(Converters.hexStringToByteArray(m)))
    .update(new Buffer(y))
    .digest('hex')

  return areByteArraysEqual(h, Converters.hexStringToByteArray(h2))
}

export const parseToken = (tokenString, website) => {
  let websiteBytes = Converters.stringToByteArray(website)
  let tokenBytes = []
  let i = 0
  let j = 0

  for (; i < tokenString.length; i += 8, j += 5) {
    let number = BigInteger(tokenString.substring(i, i + 8), 32)
    let part = Converters.hexStringToByteArray(number.toString(16))
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

  let timestamp = Converters.byteArrayToIntVal(timebytes)
  let signature = tokenBytes.slice(36, 100)
  let data = websiteBytes.concat(tokenBytes.slice(0, 36))

  let isValid = verifyBytes(signature, data, publicKey)
  publicKey = Converters.byteArrayToHexString(publicKey)

  return {
    isValid,
    timestamp,
    publicKey
  }
}

export default {
  verifyBytes,
  parseToken
}
