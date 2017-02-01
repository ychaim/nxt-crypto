import { expect } from 'chai'
import converters from '../src/converters'

describe('converters', () => {
  it('should be an object', () => {
    expect(converters).to.be.a('object')
  })

  describe('#byteArrayToIntVal', () => {
    const { byteArrayToIntVal } = converters

    it('should be a function', () => {
      expect(byteArrayToIntVal).to.be.a('function')
    })
  })

  describe('#toByteArray', () => {
    const { toByteArray } = converters

    it('should be a function', () => {
      expect(toByteArray).to.be.a('function')
    })
  })
})