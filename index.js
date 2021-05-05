'use strict'
const fs = require('fs')

const StellarSdk = require('stellar-sdk')
const stellarWallet = require("stellar-hd-wallet")
const bip39 = require("bip39")
const ssbMnemonic = require('ssb-keys-mnemonic')
const ethers = require("ethers")

const u = require('@elife/utils')

/*    way/
 * create a new secret file with a generated mnemonic
 */
function create(cb) {
  fromMnemonic(stellarWallet.generateMnemonic(), cb)
}

/*    way/
 * create a new secret file from the given mnemonic
 */
function fromMnemonic(words, cb) {
  if(!bip39.validateMnemonic(words)) return cb('Invalid mnemonic')

  const keys = ssbMnemonic.wordsToKeys(words)
  const wallet = stellarWallet.fromMnemonic(words)
  const ewallet = ethers.Wallet.fromMnemonic(words)

  const data = {
    ...keys,
    mnemonic: words,
    stellar: {
      publicKey: wallet.getPublicKey(0),
      secretKey: wallet.getSecret(0),
    },
    eth: {
      address: ewallet.address,
      publicKey: ewallet.publicKey,
      privateKey: ewallet.privateKey,
    }
  }

  write(data, cb)
}

/*      way/
 * update the secret file with the given wallet key
 * and add an eth section if not provided
 */
function updateWalletKey(secret, cb) {
  let kp
  try {
    kp = StellarSdk.Keypair.fromSecret(secret)
  } catch(e) {
    return cb(`Invalid Stellar Secret Key: ${secret}`)
  }

  loadSecretData((err, data) => {
    if(err) return cb(err)

    if(!data.eth) {
      const ewallet = ethers.Wallet.createRandom()
      data.eth = {
        address: ewallet.address,
        publicKey: ewallet.publicKey,
        privateKey: ewallet.privateKey
      }
    }

    const old = []
    if(data.stellar) {
      old.push({
        publicKey: data.stellar.publicKey,
        secretKey: data.stellar.secretKey,
      })
      if(data.stellar.old) {
        old.push(...data.stellar.old)
      }
    }
    data.stellar = {
      publicKey: kp.publicKey(),
      secretKey: kp.secret(),
    }
    if(old.length) data.stellar.old = old

    write(data, cb)

  })
}


/*      way/
 * read the secret file and - ignoring comments - parse it
 * as a JSON and return the data
 */
function loadSecretData(cb) {
  fs.readFile(u.secretFile(), 'utf8', (err, data) => {
    if(err) return cb(err)
    try {
      data = data.replace(/\s*#[^\n]*/g, "")
      cb(null, JSON.parse(data))
    } catch(e) {
      cb(e)
    }
  })
}


/*    way/
 * when writing out the secret file, set the permissions to
 * write-able before writing then remove write permissions to
 * try and keep the file safe.
 * NB: we ignore permission setting errors as they are unimportant
 */
function write(data, cb) {
    const lines = `# These are your SECRET keys.",
#
# Any one who has access to these keys has access to
# your avatar and wallets and can use it to steal from
# you and destroy your identity.
#
# NEVER show this to anyone!!!

${JSON.stringify(data, null, 2)}

# WARNING! It's vital that you DO NOT edit OR share your SECRET keys.
# You can safely share your public name or any of the other public keys.
# your public name: ${data.id}`


  fs.chmod(u.secretFile(), 0o600, err => {
    fs.writeFile(u.secretFile(), lines, err => {
      if(err) return cb(err)
      fs.chmod(u.secretFile(), 0x100, err => cb())
    })
  })
}

module.exports = {
  create,
  fromMnemonic,
  updateWalletKey,
  loadSecretData,
}
