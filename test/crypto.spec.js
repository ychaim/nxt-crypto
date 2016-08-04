import { expect } from 'chai'
import nxtCrypto from '../src'

describe('nxtCrypto', () => {
  it('should be an object', () => {
    expect(nxtCrypto).to.be.a('object')
  })

  describe('#getPublicKey()', () => {
    const { getPublicKey } = nxtCrypto
    const secretPhrase = 'test'

    it('should be a function', () => {
      expect(getPublicKey).to.be.a('function')
    })

    it('should return the correct public key', () => {
      // comparing public key taken from NXT public blockchain
      expect(getPublicKey(secretPhrase)).to.equal('d9d5c57971eefb085e3abaf7a5a4a6cdb8185f30105583cdb09ad8f61886ec65')
    })
  })

  describe('#getAccountId', () => {
    const { getAccountId } = nxtCrypto
    const publicKey = 'd9d5c57971eefb085e3abaf7a5a4a6cdb8185f30105583cdb09ad8f61886ec65'

    it('should be a function', () => {
      expect(getAccountId).to.be.a('function')
    })

    it('should return the correct numeric account id', () => {
      // comparing account id taken from NXT public blockchain
      expect(getAccountId(publicKey)).to.equal('4273301882745002507')
    })
  })

  describe('#generateSecretPhrase()', () => {
    const { generateSecretPhrase } = nxtCrypto
    const secretPhrase = generateSecretPhrase()

    it('should be a function', () => {
      expect(generateSecretPhrase).to.be.a('function')
    })

    it('should generate a secretphrase of length 128', () => {
      expect(secretPhrase).to.have.lengthOf(128)
    })
  })
})