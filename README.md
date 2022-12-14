# ReactNative BIP39 (@ns/react-native-bip39)

[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)

ReactNative-ready Mnemonic code for generating deterministic keys

## Features

- Native generation of random bytes using [react-native-randombytes](https://github.com/mvayngrib/react-native-randombytes)
- JavaScript library of crypto standards, using [crypto-js](https://github.com/brix/crypto-js)

## Reminder for developers

**_Please remember to allow recovery from mnemonic phrases that have invalid checksums (or that you don't have the wordlist)_**

When a checksum is invalid, warn the user that the phrase is not something generated by your app, and ask if they would like to use it anyway. This way, your app only needs to hold the wordlists for your supported languages, but you can recover phrases made by other apps in other languages.

However, there should be other checks in place, such as checking to make sure the user is inputting 12 words or more separated by a space. ie. `phrase.trim().split(/\s+/g).length >= 12`

## Examples

```js
import bip39 from '@ns/react-native-bip39';

bip39.mnemonicToSeedHex('basket actual');
// => '5cf2d4a8b0355e90295bdfc565a022a409af063d5365bb57bf74d9528f494bfa4400f53d8349b80fdae44082d7f9541e1dba2b003bcfec9d0d53781ca676651f'

bip39.mnemonicToSeed('basket actual');
// => <Buffer 5c f2 d4 a8 b0 35 5e 90 29 5b df c5 65 a0 22 a4 09 af 06 3d 53 65 bb 57 bf 74 d9 52 8f 49 4b fa 44 00 f5 3d 83 49 b8 0f da e4 40 82 d7 f9 54 1e 1d ba 2b ...>

bip39.validateMnemonic(myMnemonic);
// => true

bip39.validateMnemonic('basket actual');
// => false
```

```js
import bip39 from 'react-native-bip39';

// defaults to BIP39 English word list
// uses HEX strings for entropy
const mnemonic = bip39.entropyToMnemonic('133755ff');
// => basket rival lemon

// reversible
bip39.mnemonicToEntropy(mnemonic);
// => '133755ff'
```
