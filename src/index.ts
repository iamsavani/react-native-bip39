import { Buffer } from 'buffer';
import createHash from 'create-hash';
import crypto from 'crypto-js';
import { NativeModules } from 'react-native';
import DEFAULT_WORDLIST from '../wordlists/en.json';
import SPANISH_WORDLIST from '../wordlists/es.json';
import JAPANESE_WORDLIST from '../wordlists/ja.json';

const INVALID_MNEMONIC = 'Invalid mnemonic';
const INVALID_ENTROPY = 'Invalid entropy';
const INVALID_CHECKSUM = 'Invalid mnemonic checksum';
const WORDLIST_REQUIRED =
  'A wordlist is required but a default could not be found.\n' +
  'Please pass a 2048 word array explicitly.';

export const mnemonicToSeed = (
  mnemonic: string,
  password?: string,
  iterations = 1
) =>
  crypto.PBKDF2(normalize(mnemonic), salt(normalize(password)), {
    hasher: crypto.algo.SHA512,
    keySize: 512 / 32,
    iterations,
  });

export const mnemonicToSeedHex = (
  mnemonic: string,
  password?: string,
  iterations = 2048
) => mnemonicToSeed(mnemonic, password, iterations).toString(crypto.enc.Hex);

const bytesToBinary = (bytes: number[]) =>
  bytes.map((x) => lpad(x.toString(2), '0', 8)).join('');

export const entropyToMnemonic = (
  entropy: string | Buffer,
  wordlist: string[] = DEFAULT_WORDLIST
) => {
  if (typeof entropy === 'string') entropy = Buffer.from(entropy, 'hex');
  if (!wordlist) {
    throw new Error(WORDLIST_REQUIRED);
  }

  // 128 <= ENT <= 256
  if (entropy.length < 16) {
    throw new TypeError(INVALID_ENTROPY);
  }
  if (entropy.length > 32) {
    throw new TypeError(INVALID_ENTROPY);
  }
  if (entropy.length % 4 !== 0) {
    throw new TypeError(INVALID_ENTROPY);
  }

  const entropyBits = bytesToBinary(Array.from(entropy));
  const checksum = deriveChecksumBits(entropy);
  const bits = entropyBits + checksum;
  const words = bits
    .match(/(.{1,11})/g)!
    .map((binary) => wordlist![binaryToByte(binary)]);

  return wordlist[0] === '\u3042\u3044\u3053\u304f\u3057\u3093' // Japanese wordlist
    ? words.join('\u3000')
    : words.join(' ');
};

export const mnemonicToEntropy = (
  mnemonic: string,
  wordlist: string[] = DEFAULT_WORDLIST
) => {
  const words = normalize(mnemonic).split(' ');
  if (words.length % 3 !== 0) {
    throw new Error(INVALID_MNEMONIC);
  }
  // convert word indices to 11 bit binary strings
  const bits = words
    .map((word) => {
      const index = wordlist!.indexOf(word);
      if (index === -1) {
        throw new Error(INVALID_MNEMONIC);
      }
      return lpad(index.toString(2), '0', 11);
    })
    .join('');

  // convert word indices to 11 bit binary strings
  const dividerIndex = Math.floor(bits.length / 33) * 32;
  const entropy = bits.slice(0, dividerIndex);
  const checksum = bits.slice(dividerIndex);

  // calculate the checksum and compare
  const entropyBytes = entropy.match(/(.{1,8})/g)!.map(binaryToByte);

  if (entropyBytes.length < 16) {
    throw new Error(INVALID_ENTROPY);
  }
  if (entropyBytes.length > 32) {
    throw new Error(INVALID_ENTROPY);
  }
  if (entropyBytes.length % 4 !== 0) {
    throw new Error(INVALID_ENTROPY);
  }

  const entropyBuffer = Buffer.from(entropyBytes);
  const newChecksum = deriveChecksumBits(entropyBuffer);

  if (newChecksum !== checksum) throw new Error(INVALID_CHECKSUM);
  return entropyBuffer.toString('hex');
};

export const generateMnemonic = (
  strength = 128,
  rng?: (size: number) => Buffer,
  wordlist?: string[]
) => {
  if (strength % 32 !== 0) {
    throw new TypeError(INVALID_ENTROPY);
  }
  const randomBase64 = NativeModules.RNGetRandomValues.getRandomBase64(
    strength / 8
  );
  const randomBytesBuffer = rng
    ? rng(strength / 8)
    : Buffer.from(randomBase64, 'base64');
  return entropyToMnemonic(randomBytesBuffer, wordlist);
};

export const validateMnemonic = (mnemonic: string, wordlist?: string[]) => {
  try {
    mnemonicToEntropy(mnemonic, wordlist);
  } catch (e) {
    return false;
  }
  return true;
};

const deriveChecksumBits = (entropyBuffer: Buffer): string => {
  // Calculated constants from BIP39
  const ENT = entropyBuffer.length * 8;
  const CS = ENT / 32;
  const hash = createHash('sha256').update(entropyBuffer).digest();
  return bytesToBinary(Array.from(hash)).slice(0, CS);
};

const salt = (password?: string) => 'mnemonic' + (password || '');

const lpad = (str: string, padString: string, length: number) => {
  while (str.length < length) str = padString + str;
  return str;
};

const binaryToByte = (bin: string): number => parseInt(bin, 2);

const normalize = (str = ''): string => str.normalize('NFKD');

export const wordlists = {
  EN: DEFAULT_WORDLIST,
  ES: SPANISH_WORDLIST,
  JA: JAPANESE_WORDLIST,
};
