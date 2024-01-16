const fs = require('fs'); // Import the 'fs' module for file operations

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
      const randomIndex = this.getRandomInt(charset.length);
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
   * Constructor for the CipherForge class.
   */
  constructor() {
    // Path to the dictionary file
    this.dictionaryFilePath = path.join(__dirname, 'psw.txt');
    // Load the dictionary from the file
    this.dictionary = this.loadDictionary();
  }

  /**
   * Load the dictionary from the file.
   *
   * @returns {string} - Loaded dictionary as a string.
   */
  loadDictionary() {
    try {
      // Read the file synchronously and process the data
      const data = fs.readFileSync(this.dictionaryFilePath, 'utf-8');
      // Split the data into an array of words, trim whitespace, and remove empty words
      const wordsArray = data.split(/\r?\n/).map(word => word.trim()).filter(word => word !== '');
      // Convert the array of words back to a string
      const wordsString = wordsArray.join(',');

      return wordsString;

    } catch (error) {
      // Handle errors during dictionary loading
      console.error(`Error reading the file ${this.dictionaryFilePath}: ${error.message}`);
      return '';
    }
  }

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
    const totalScore = parseFloat((lengthScore * 0.33) + (diversityScore * 0.33) + (specialCharactersScore * 0.33) + (dictionaryScore * 0.33).toFixed(2));

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
    const maxLength = 20;

    const length = password.length;
    if (length < minLength) return 0;
    if (length > maxLength) return 50;
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
      return score + (set.test(password) ? 25 : 0);
    }, 0);

    // Check for number or letter sequences and penalize
    const hasNumberSequence = /\d{3}/.test(password);
    const hasLetterSequence = /abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/i.test(password);
    if (hasNumberSequence || hasLetterSequence) {
      diversityScore = 0;
    }

    return diversityScore;
  }

  /**
   * Calculate the special characters score for a password.
   *
   * @param {string} password - Password to calculate the special characters score for.
   * @returns {number} - Special characters score for the password.
   */
  _calculateSpecialCharactersScore(password) {
    // Regular expression for detecting special characters
    const specialCharacters = /[!@#$%^&*()_+\-=\[\]{}|;':",.<>\/?]+/;
  
    return specialCharacters.test(password) ? 25 + 25 : 0;
  }

  /**
   * Calculate the dictionary score for a password.
   *
   * @param {string} password - Password to calculate the dictionary score for.
   * @returns {number} - Dictionary score for the password.
   */
  _calculateDictionaryScore(password) {
    // Normalize the password and obtain words from the dictionary
    const normalizedPassword = password.replace(/\s+/g, '').toLowerCase();
    const wordsInDictionary = this.dictionary
        .toLowerCase()
        .match(/\b\w+\b/g);

    if (!wordsInDictionary || wordsInDictionary.length === 0) {
        return 100; 
    }

    let wordsPresentInString = 0;

    wordsInDictionary.forEach(word => {
      // Create a regular expression for exact word match
      const regex = new RegExp(`\\b${word}\\b`);
      if (regex.test(normalizedPassword)) {
        wordsPresentInString++;
      }
    });

    // Calculate the percentage of words present in the password
    const percentage = (wordsPresentInString / wordsInDictionary.length) * 100 || 100;
    return percentage;
  }
}


module.exports = {
    CipherCraft, CipherForge
}
