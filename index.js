const fs = require('fs'); // Import the 'fs' module for file operations
const psw = require('./psw.js')
class CipherCraft {
  constructor() {
    // Define character sets
    this.charsets = {
      lowercase: 'abcdefghijklmnopqrstuvwxyz',
      uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
      numeric: '0123456789',
      symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?',
    };
  }

  /**
   * Generates a custom password based on specified options.
   *
   * @param {Object} options - Options for password generation.
   *   @property {number} length - Length of the password.
   *   @property {boolean} useLowercase - Include lowercase characters.
   *   @property {boolean} useUppercase - Include uppercase characters.
   *   @property {boolean} useNumbers - Include numeric characters.
   *   @property {boolean} useSymbols - Include symbol characters.
   *   @property {string} customCharset - Custom character set.
   * @returns {string} - Generated password.
   */
  CustomPassword(options = {}) {
    const {
      length = 12,
      useLowercase = true,
      useUppercase = true,
      useNumbers = true,
      useSymbols = true,
      customCharset = '',
    } = options;

    let charset = customCharset;

    if (useLowercase) charset += this.charsets.lowercase;
    if (useUppercase) charset += this.charsets.uppercase;
    if (useNumbers) charset += this.charsets.numeric;
    if (useSymbols) charset += this.charsets.symbols;

    return this.generatePassword(charset, length);
  }

  /**
   * Generates a basic password from the given character set and length.
   *
   * @param {string} charset - Character set for password generation.
   * @param {number} length - Length of the password.
   * @returns {string} - Generated password.
   */
  BasicPassword(charset, length) {
    let password = '';
    for (let i = 0; i < length; i++) {
      const randomIndex = this.RandInt(charset.length);
      password += charset[randomIndex];
    }
    return password;
  }

  /**
   * Generates a cryptographic key with a specified length.
   *
   * @param {number} length - Length of the key.
   * @returns {string} - Generated key.
   */
  Key(length = 32) {
    // Define character set for key generation
    const charset = 'abcdef0123456789';
    return this.generatePassword(charset, length);
  }

  /**
   * Generates a random integer within the specified range.
   *
   * @param {number} max - Maximum value (exclusive).
   * @returns {number} - Random integer.
   */
  RandInt(max) {
    const randomBytes = this._getRandomBytes(4);
    const randomValue = this._bytesToNumber(randomBytes);
    return randomValue % max;
  }

  /**
   * Generates an array of random bytes with the specified length.
   *
   * @param {number} length - Length of the random bytes array.
   * @returns {Uint8Array} - Array of random bytes.
   */
  _getRandomBytes(length) {
    const randomBytes = Array.from({ length }, () => Math.floor(Math.random() * 256));
    return Uint8Array.from(randomBytes);
  }

  /**
   * Converts an array of bytes to a number.
   *
   * @param {Uint8Array} bytes - Array of bytes.
   * @returns {number} - Converted number.
   */
  _bytesToNumber(bytes) {
    let result = 0;
    for (let i = 0; i < bytes.length; i++) {
      result = (result << 8) | bytes[i];
    }
    return result >>> 0;
  }
}

class CipherForge {
  /**
   * Test the security of a given password.
   *
   * @param {string} password - Password to test.
   * @returns {Object} - Security assessment result.
   */
  Test(password) {
    // Calculate individual scores
    const lengthScore = parseFloat(this._calculateLengthScore(password).toFixed(2));
    const diversityScore = parseFloat(this._calculateDiversityScore(password).toFixed(2));
    const specialCharactersScore = parseFloat(this._calculateSpecialCharactersScore(password).toFixed(2));
    const dictionaryScore = parseFloat(this._calculateDictionaryScore(password).toFixed(2));

    // Calculate the total score
    const totalScore = parseFloat(((lengthScore * 0.25) + (diversityScore * 0.25) + (specialCharactersScore * 0.25) + (dictionaryScore * 0.25)).toFixed(2));

    // Return the security assessment
    return {
      isSecure: totalScore >= 52,
      totalScore,
      details: {
        lengthScore,
        diversityScore,
        specialCharactersScore,
        dictionaryScore,
      },
    };
  }

  /**
   * Calculate the length score for a password.
   *
   * @param {string} password - Password to calculate the length score for.
   * @returns {number} - Length score for the password.
   */
  _calculateLengthScore(password) {
    // Constants for minimum and maximum password lengths
    const minLength = 8;
    const maxLength = 30;

    const length = password.length;
    if (length < minLength) return 0;
    if (length > maxLength) return 100;
    return ((length - minLength) / (maxLength - minLength)) * 50 + 25;
  }

  /**
   * Calculate the diversity score for a password.
   *
   * @param {string} password - Password to calculate the diversity score for.
   * @returns {number} - Diversity score for the password.
   */
  _calculateDiversityScore(password) {
    // Character sets representing lowercase letters, uppercase letters, digits, and special characters
    const characterSets = [
      /[a-z]/,
      /[A-Z]/,
      /\d/,
      /\W/,
    ];
  
    let diversityScore = characterSets.reduce((score, set) => {
      return score + (set.test(password) ? 50 : 0);
    }, 0);
  
    // Check for repetitive number or letter sequences and penalize
    const hasRepetitiveSequence = /(\w)\1{2,}/.test(password);
    if (hasRepetitiveSequence) {
      diversityScore = 0;
    }
  
    // Check for consecutive sequences of at least 3 letters
    const hasConsecutiveLetterSequence = /[a-zA-Z]{3,}/.test(password);
    if (hasConsecutiveLetterSequence) {
      diversityScore += 50;
    }
  
    // Ensure the diversity score is capped at 100
    diversityScore = Math.min(diversityScore, 100);
  
    return diversityScore;
  }
  

  /**
   * Calculate the special characters score for a password.
   *
   * @param {string} password - Password to calculate the special characters score for.
   * @returns {number} - Special characters score for the password.
   */
  _calculateSpecialCharactersScore(password) {
    // Regular expression to match any special character
    const specialCharactersRegex = /[^a-zA-Z0-9]/;
  
    // Count the total number of characters and the number of special characters
    const totalCharacters = password.length;
    let specialCharactersCount = 0;
  
    // Iterate through each character in the password
    for (let i = 0; i < totalCharacters; i++) {
      const currentChar = password[i];
  
      // Check if the current character is a special character
      if (specialCharactersRegex.test(currentChar)) {
        specialCharactersCount++;
      }
    }
  
    // Calculate the percentage of special characters in the password
    const percentageSpecialCharacters = (specialCharactersCount / totalCharacters) * 100;
  
    // Ensure the score is not greater than 100%
    const specialCharactersScore = Math.min(percentageSpecialCharacters, 100);
  
    console.log(`Special Characters Score: ${specialCharactersScore}`);
    return specialCharactersScore;
  }

  /**
   * Calculate the dictionary score for a password.
   *
   * @param {string} password - Password to calculate the dictionary score for.
   * @returns {number} - Dictionary score for the password.
   */
  _calculateDictionaryScore(password) {
    // Normalize the password and obtain words from the dictionary
    let characterCountInDictionary = 0;
    let uniqueWordsInPassword = [];
  
    // Iterate through each word in the password
    for (let i = 0; i < psw.pwd.length; i++) {
      const word = psw.pwd[i];
      const alphanumericRegex = /^[a-zA-Z0-9]+$/;
  
      // Check if the word is alphanumeric
      if (alphanumericRegex.test(word)) {
        // Create a regex to match the whole word in the password
        const regex = new RegExp('\\b(' + word + ')\\b', 'g');
        let matches = password.match(regex);
  
        // Check if there are matches and the word is not already in the uniqueWords array
        if (matches && !uniqueWordsInPassword.includes(word)) {
          uniqueWordsInPassword.push(word);
          characterCountInDictionary += word.length;
        }
      }
    }
    // Calculate the password score as the percentage of characters not in the dictionary
    const score = 100 - ((characterCountInDictionary / password.length) * 100);
    return score;

  }
}


module.exports = {
    CipherCraft, CipherForge
}
