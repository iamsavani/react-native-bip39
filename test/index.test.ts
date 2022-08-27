import { Buffer } from 'buffer';
import crypto from 'crypto-js';
import * as bip39 from '../src/';
import vectors from './vectors.json';
const WORDLISTS = {
  english: require('../wordlists/en.json'),
  japanese: require('../wordlists/ja.json'),
  custom: require('./wordlist.json'),
};

type Vector = string[];

const randomString = (length: number) =>
  [...Array(length)].map(() => (~~(Math.random() * 36)).toString(36)).join('');

const mockGetRandomBase64 = jest.fn((length: number) =>
  btoa(randomString(length))
);

jest.mock('react-native', () => ({
  Platform: {
    select: () => '',
  },
  NativeModules: {
    RNGetRandomValues: {
      getRandomBase64: (length: number) => mockGetRandomBase64(length),
    },
  },
}));

const testVector = (
  description: string,
  wordlist: string[] | undefined,
  password: string | undefined,
  v: Vector,
  i: number
) => {
  const ventropy = v[0];
  const vmnemonic = v[1];
  const vseedHex = v[2];
  const rng = () => {
    return Buffer.from(ventropy, 'hex');
  };
  test(`for ${description} (${i}), ${ventropy}`, () => {
    expect(bip39.mnemonicToEntropy(vmnemonic, wordlist)).toEqual(ventropy);
    expect(bip39.mnemonicToSeedHex(vmnemonic, password)).toEqual(vseedHex);
    expect(bip39.entropyToMnemonic(ventropy, wordlist)).toEqual(vmnemonic);
    expect(bip39.generateMnemonic(undefined, rng, wordlist)).toBe(vmnemonic);
    expect(bip39.validateMnemonic(vmnemonic, wordlist)).toBe(true);
  });
};

vectors.english.forEach((v, i) =>
  testVector('English', undefined, 'TREZOR', v, i)
);
vectors.japanese.forEach((v, i) =>
  testVector(
    'Japanese',
    WORDLISTS.japanese,
    '㍍ガバヴァぱばぐゞちぢ十人十色',
    v,
    i
  )
);
vectors.custom.forEach((v, i) =>
  testVector('Custom', WORDLISTS.custom, undefined, v, i)
);

test('invalid entropy', () => {
  expect(() => bip39.entropyToMnemonic(Buffer.from('', 'hex'))).toThrowError(
    /^Invalid entropy$/
  );
  expect(() =>
    bip39.entropyToMnemonic(Buffer.from('000000', 'hex'))
  ).toThrowError(/^Invalid entropy$/);
  expect(() =>
    bip39.entropyToMnemonic(Buffer.from(new Array(1028 + 1).join('00'), 'hex'))
  ).toThrowError(/^Invalid entropy$/);
});

test('UTF8 passwords', () => {
  vectors.japanese.forEach((v) => {
    const vmnemonic = v[1];
    const vseedHex = v[2];

    const password = '㍍ガバヴァぱばぐゞちぢ十人十色';
    const normalizedPassword =
      'メートルガバヴァぱばぐゞちぢ十人十色';
    expect(
      bip39.mnemonicToSeed(vmnemonic, password, 2048).toString(crypto.enc.Hex)
    ).toBe(vseedHex);
    expect(
      bip39
        .mnemonicToSeed(vmnemonic, normalizedPassword, 2048)
        .toString(crypto.enc.Hex)
    ).toBe(vseedHex);
  });
});

test('generateMnemonic can vary entropy length', () => {
  const words = bip39.generateMnemonic(160).split(' ');
  expect(words.length).toBe(15);
});

test('generateMnemonic throws invalid entropy', () => {
  expect(() => bip39.generateMnemonic(6)).toThrowError(/^Invalid entropy$/);
});

test('validateMnemonic', () => {
  expect(bip39.validateMnemonic('sleep kitten')).toBe(false);
  expect(bip39.validateMnemonic('sleep kitten sleep kitten sleep kitten')).toBe(
    false
  );
  expect(
    bip39.validateMnemonic(
      'turtle front uncle idea crush write shrug there lottery flower risky shell'
    )
  ).toBe(false);
  expect(
    bip39.validateMnemonic(
      'sleep kitten sleep kitten sleep kitten sleep kitten sleep kitten sleep kitten'
    )
  ).toBe(false);
});

test('exposes standard wordlists', () => {
  expect(bip39.wordlists.EN.length).toEqual(2048);
  expect(typeof bip39.wordlists.EN[0]).toBe('string');
  expect(bip39.wordlists.EN).toEqual(WORDLISTS.english);
});
