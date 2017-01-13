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

  describe('#getAccountRS', () => {
    const { getAccountRS } = nxtCrypto
    const publicKey = 'd9d5c57971eefb085e3abaf7a5a4a6cdb8185f30105583cdb09ad8f61886ec65'

    it('should be a function', () => {
      expect(getAccountRS).to.be.a('function')
    })

    it('should return the correct account reed solomon', () => {
      expect(getAccountRS(publicKey)).to.equal('NXT-E8JD-FHKJ-CQ9H-5KGMQ')
    })

    it('should return the correct account reed solomon with a different prefix', () => {
      expect(getAccountRS(publicKey, 'DBN')).to.equal('DBN-E8JD-FHKJ-CQ9H-5KGMQ')
    })
  })

  describe('#getAccountRSFromSecretPhrase', () => {
    const { getAccountRSFromSecretPhrase } = nxtCrypto
    const secretPhrase = 'test'


    it('should be a function', () => {
      expect(getAccountRSFromSecretPhrase).to.be.a('function')
    })

    it('should return the correct account reed solomon', () => {
      expect(getAccountRSFromSecretPhrase(secretPhrase)).to.equal('NXT-E8JD-FHKJ-CQ9H-5KGMQ')
    })

    it('should return the correct account reed solomon with a different prefix', () => {
      expect(getAccountRSFromSecretPhrase(secretPhrase, 'DBN')).to.equal('DBN-E8JD-FHKJ-CQ9H-5KGMQ')
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

  describe('#sha256()', () => {
    const { sha256 } = nxtCrypto

    it('should be a function', () => {
      expect(sha256).to.be.a('function')
    })

    it('should generate a hash of length 64', () => {
      expect(sha256('test')).to.have.lengthOf(64)
    })

    it('should generate a correct hash', () => {
      expect(sha256('test')).to.equal('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')
    })
  })
})
