# Cipher Forge Librairy Documentation
[![npm version](https://img.shields.io/npm/v/cipherforge)]([https://www.npmjs.com/package/cipherforge](https://www.npmjs.com/package/cipherforge))
[![Downloads](https://img.shields.io/npm/dt/cipherforge)]([https://www.npmjs.com/package/cipherforge)
## Introduction
The Cipher Forge library is designed to provide functionality for password and cryptographic key generation, along with security testing features.

## Classes 
CipherCraft
    Core class for password and key generation.

 CipherForge
    Class for testing the security of passwords.

## Getting Started
### Installation
```bash
npm install cipherforge
```

### Importing 
```javascript
const {CipherCraft, CipherForge} = require('cipherforge');
const craft = new CipherCraft();
const forge = new CipherForge();
```





# CipherCraft Class

## Methods

### CustomPassword(options: object): string

Generates a custom password based on specified options.

#### Parameters:

- `options` (optional): An object with the following properties:
  - `length` (number, default: 12): Length of the password.
  - `useLowercase` (boolean, default: true): Include lowercase characters.
  - `useUppercase` (boolean, default: true): Include uppercase characters.
  - `useNumbers` (boolean, default: true): Include numeric characters.
  - `useSymbols` (boolean, default: true): Include symbol characters.
  - `customCharset` (string, default: ''): Custom character set.

#### Returns:

A generated password.

## Example 
```javascript
const customPassword = cipher.CustomPassword({
  length: 16,
  useLowercase: true,
  useUppercase: true,
  useNumbers: true,
  useSymbols: true,
});
```


### BasicPassword(charset: string, length: number): string

Generates a basic password from the given character set and length.

#### Parameters:

- `charset` (string): Character set for password generation.
- `length` (number): Length of the password.

#### Returns:

A generated password.
## Example 
```javascript
const basicPassword = cipher.BasicPassword(cipher.charsets.lowercase + cipher.charsets.numeric, 10);
```

### Key(length: number): string

Generates a cryptographic key with a specified length.

#### Parameters:

- `length` (number, default: 32): Length of the key.

#### Returns:

A generated key.
## Example 
```javascript
const cryptographicKey = cipher.Key();

```

### RandInt(max: number): number

Generates a random integer within the specified range.

#### Parameters:

- `max` (number): Maximum value (exclusive).

#### Returns:

A random integer.

## Example 
```javascript
const cryptographicKey = cipher.RandInt(32);
```





# CipherForge Class

## Methods

### Test(password: string): object

Tests the security of a password based on various criteria.

#### Parameters:

- `password` (string): Password to test.

#### Returns:

An object containing security information.
## Example
```javascript


const passwordToTest = 'SecurePassword123!';

// Test the security of the password
const securityInfo = forge.Test(passwordToTest);

console.log('Security Information:', securityInfo);

{
  isSecure: true, // or false
  totalScore: 85,
  details: {
    lengthScore: 40,
    diversityScore: 25,
    specialCharactersScore: 20,
    dictionaryScore: 0,
  },
}
```
