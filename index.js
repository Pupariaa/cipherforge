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
  constructor() {
    // Define the path to the dictionary file
    this.dictionaryFilePath = path.join(require.main.path, 'node_modules', 'cipherforge', 'psw.txt');
    // Load the dictionary from the file into a Set
    this.dictionary = new Set(this.loadDictionary());
  }

  /**
   * Loads the dictionary from the file.
   *
   * @returns {Array} - Array of dictionary words.
   */
  loadDictionary() {
    try {
      // Read the file synchronously and split words based on newline characters
      const data = fs.readFileSync(this.dictionaryFilePath, 'utf-8');
      return data.split(/\r?\n/).filter(word => word.trim() !== '');
    } catch (error) {
      // Handle errors during file reading
      console.error(`Error reading file ${this.dictionaryFilePath}: ${error.message}`);
      return [];
    }
  }

  /**
   * Tests the security of a password based on various criteria.
   *
   * @param {string} password - Password to test.
   * @returns {Object} - Object containing security information.
   */
  Test(password) {
    // Calculate individual scores
    const lengthScore = this.calculateLengthScore(password);
    const diversityScore = this.calculateDiversityScore(password);
    const specialCharactersScore = this.calculateSpecialCharactersScore(password);
    const dictionaryScore = this.calculateDictionaryScore(password);

    // Calculate total score
    const totalScore = lengthScore + diversityScore + specialCharactersScore + dictionaryScore;

    // Return security information
    return {
      isSecure: totalScore >= 75,
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
   * Calculates the length score of a password.
   *
   * @param {string} password - Password to evaluate.
   * @returns {number} - Length score.
   */
  calculateLengthScore(password) {
    // Define minimum and maximum password lengths
    const minLength = 8;
    const maxLength = 20;

    const length = password.length;
    if (length < minLength) return 0;
    if (length > maxLength) return 50;

    // Calculate and return the length score
    return ((length - minLength) / (maxLength - minLength)) * 50;
  }

  /**
   * Calculates the diversity score of a password.
   *
   * @param {string} password - Password to evaluate.
   * @returns {number} - Diversity score.
   */
  calculateDiversityScore(password) {
    // Define character sets to check for diversity
    const characterSets = [
      /[a-z]/,
      /[A-Z]/,
      /\d/,
      /\W/,
    ];

    // Calculate diversity score based on character sets
    const diversityScore = characterSets.reduce((score, set) => {
      return score + (set.test(password) ? 25 : 0);
    }, 0);

    return diversityScore;
  }

  /**
   * Calculates the score for the presence of special characters in a password.
   *
   * @param {string} password - Password to evaluate.
   * @returns {number} - Special characters score.
   */
  calculateSpecialCharactersScore(password) {
    // Define a regular expression for special characters
    const specialCharacters = /[!@#$%^&*()_+\-=\[\]{}|;':",.<>\/?]+/;
    return specialCharacters.test(password) ? 25 : 0;
  }

  /**
   * Calculates the dictionary score of a password.
   *
   * @param {string} password - Password to evaluate.
   * @returns {number} - Dictionary score.
   */
  calculateDictionaryScore(password) {
    // Convert the password to lowercase for case-insensitive comparison
    const lowercasePassword = password.toLowerCase();
    // Split the password into words using non-word characters
    const wordsInPassword = lowercasePassword.split(/\W+/);
    // Filter matching words from the dictionary
    const matchingWords = wordsInPassword.filter(word => this.dictionary.has(word));
    // Calculate and return the dictionary score
    const dictionaryScore = Math.max(0, 50 - matchingWords.length * 10);
    return dictionaryScore;
  }
}


module.exports = {
    CipherCraft, CipherForge
}
