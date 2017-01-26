import BigInteger from 'big-integer'

let charToNibble = {}
let nibbleToChar = []
let i
for (i = 0; i <= 9; ++i) {
  let character = i.toString()
  charToNibble[character] = i
  nibbleToChar.push(character)
}
for (i = 10; i <= 15; ++i) {
  let lowerChar = String.fromCharCode('a'.charCodeAt(0) + i - 10)
  let upperChar = String.fromCharCode('A'.charCodeAt(0) + i - 10)

  charToNibble[lowerChar] = i
  charToNibble[upperChar] = i
  nibbleToChar.push(lowerChar)
}

export const byteArrayToIntVal = (byteArray) => {
  let intval = 0

  for (let index = 0; index < byteArray.length; index++) {
    let byt = byteArray[index] & 0xFF
    let value = byt * Math.pow(256, index)
    intval += value
  }
  return intval
}

export const byteArrayToHexString = (byteArray) => {
  let str = ''

  for (let i = 0; i < byteArray.length; ++i) {
    if (byteArray[i] < 0) {
      byteArray[i] += 256
    }
    str += nibbleToChar[byteArray[i] >> 4] + nibbleToChar[byteArray[i] & 0x0F]
  }
  return str
}

export const stringToByteArray = (str) => {
  str = unescape(encodeURIComponent(str))
  let bytes = new Array(str.length)
  for (let i = 0; i < str.length; ++i) {
    bytes[i] = str.charCodeAt(i)
  }
  return bytes
}

export const hexStringToByteArray = (str) => {
  let byteArray = []
  let i = 0
  if (str.length % 2 !== 0) {
    byteArray.push(charToNibble[str.charAt(0)])
    ++i
  }
  for (; i < str.length - 1; i += 2) {
    byteArray.push((charToNibble[str.charAt(i)] << 4) + charToNibble[str.charAt(i + 1)])
  }
  if (byteArray.length < 5) {
    byteArray.unshift(0)
  }
  return byteArray
}

export const stringToHexString = (str) => {
  return byteArrayToHexString(stringToByteArray(str))
}

export const byteArrayToBigInteger = (byteArray) => {
  let value = new BigInteger('0', 10)
  let temp1
  let temp2

  for (let i = byteArray.length - 1; i >= 0; i--) {
    temp1 = value.multiply(new BigInteger('256', 10))
    temp2 = temp1.add(new BigInteger(byteArray[i].toString(10), 10))
    value = temp2
  }

  return value
}

export default {
  byteArrayToIntVal,
  byteArrayToHexString,
  byteArrayToBigInteger,
  stringToByteArray,
  hexStringToByteArray,
  stringToHexString
}
