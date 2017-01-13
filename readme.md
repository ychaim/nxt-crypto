# Nxt Crypto

ES6 library for Nxt crypto


## API

### parseToken(tokenString, dataString)
Pass in the token string and data string to compare to see if it's a valid token.

Returns
```
{
  isValid: true/false
  timestamp: nxt timestamp
  publicKey: publickey of account that created the token
}
```

### getPublicKey(secretPhrase)
Returns the public key of the passed in secretphrase

### getAccountId(publicKey)
Returns numeric accountId belonging to the publicKey

### getAccountRS(publicKey, prefix = 'NXT')
Returns Reed Solomon accountId belonging to the publicKey

### getAccountRSFromSecretPhrase(secretPhrase, prefix = 'NXT')
Returns Reed Solomon accountId belonging to the secretPhrase

### generateSecretPhrase(generateSecretPhrase)
Returns an 128 bytes random secretphrase

### encrypt(message, key)
Encrypts a string message with the given string key.

### decrypt(encryptedMessage, key)
Decrypt a encrypted object with the given string key.
