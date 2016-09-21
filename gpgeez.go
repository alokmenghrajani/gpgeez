package gpgeez

import (
  "bytes"
  "time"

  "golang.org/x/crypto/openpgp"
  "golang.org/x/crypto/openpgp/armor"
  "golang.org/x/crypto/openpgp/packet"
)

type Config struct {
  packet.Config
  Expiry time.Duration
}

type Key struct {
  openpgp.Entity
}

// It's weird that I can't find these constants anywhere in golang.org/x/crypto/openpgp
// They ought to exist there?
// Values from https://tools.ietf.org/html/rfc4880#section-9
const (
  MD5 = 1
  SHA1 = 2
  RIPEMD160 = 3
  SHA256 = 8
  SHA384 = 9
  SHA512 = 10
  SHA224 = 11
)

/**
 * CreateKey creates a GPG key which is similar to running GnuPG's
 * gpg --gen-key command line tool.
 *
 * I.e. this method returns a primary signing key, an encryption subkey, a bunch of self-signatures
 *      and information such as ciphers to use, expiry, etc.
 *
 * There are a few differences:
 * - GnuPG sets key server preference to 0x80, no-modify (see https://tools.ietf.org/html/rfc4880#section-5.2.3.17)
 * - GnuPG sets features to 0x01, modification detection (see https://tools.ietf.org/html/rfc4880#page-36)
 * - issuer key ID is hashed subpkt instead of subpkt
 * - GnuPG sets the digest algorithm to SHA1. Go defaults to SHA256.
 * - GnuPG includes Bzip2 as a compression method. Golang currently doesn't suppoer Bzip2, so
 *   that option isn't set.
 * - contains a primary user ID sub packet.
 *
 * You can see these differences for yourself by comparing the output of:
 *   go run example/create_key.go | gpg --homedir /tmp --list-packets
 * with:
 *   gpg --homedir /tmp --gen-key; gpg --homedir /tmp -a --export | gpg --homedir /tmp --list-packets
 *
 * Or just look at https://github.com/alokmenghrajani/gpgeez/blob/master/gpgeez_test.pl
 *
 * Some useful links:
 * https://davesteele.github.io/gpg/2014/09/20/anatomy-of-a-gpg-key/
 * http://stackoverflow.com/questions/29929750/go-golang-openpg-create-key-pair-and-create-signature
 * https://github.com/golang/go/issues/12153
 */
func CreateKey(name, comment, email string, config *Config) (*Key, error) {
  // Create the key
  key, err := openpgp.NewEntity(name, comment, email, &config.Config)
  if err != nil {
    return nil, err
  }

  // Set expiry and algorithms. Self-sign the identity.
  dur := uint32(config.Expiry.Seconds())
  for _, id := range key.Identities {
    id.SelfSignature.KeyLifetimeSecs = &dur

    id.SelfSignature.PreferredSymmetric = []uint8{
      uint8(packet.CipherAES256),
      uint8(packet.CipherAES192),
      uint8(packet.CipherAES128),
      uint8(packet.CipherCAST5),
      uint8(packet.Cipher3DES),
    }

    id.SelfSignature.PreferredHash = []uint8{
      SHA256,
      SHA1,
      SHA384,
      SHA512,
      SHA224,
    }

    id.SelfSignature.PreferredCompression = []uint8{
      uint8(packet.CompressionZLIB),
      uint8(packet.CompressionZIP),
    }

    err := id.SelfSignature.SignUserId(id.UserId.Id, key.PrimaryKey, key.PrivateKey, &config.Config)
    if err != nil {
      return nil, err
    }
  }

  // Self-sign the Subkeys
  for _, subkey := range key.Subkeys {
    subkey.Sig.KeyLifetimeSecs = &dur
    err := subkey.Sig.SignKey(subkey.PublicKey, key.PrivateKey, &config.Config)
    if err != nil {
      return nil, err
    }
  }

  r := Key{*key}
  return &r, nil
}

/**
 * Returns the public part of a Key in armor format.
 */
func (key *Key) Armor() (string, error) {
  buf := new(bytes.Buffer)
  armor, err := armor.Encode(buf, openpgp.PublicKeyType, nil)
  if err != nil {
    return "", err
  }
  key.Serialize(armor)
  armor.Close()

  return buf.String(), nil
}

/**
 * Returns the private part of a Key in armor format.
 *
 * Note: if you want to protect the string against varous low-level attacks, you should look at
 * https://github.com/stouset/go.secrets and https://github.com/worr/secstring
 * and then re-implement this function.
 */
 func (key *Key) ArmorPrivate(config *Config) (string, error) {
   buf := new(bytes.Buffer)
   armor, err := armor.Encode(buf, openpgp.PrivateKeyType, nil)
   if err != nil {
     return "", err
   }
   c := config.Config
   key.SerializePrivate(armor, &c)
   armor.Close()

   return buf.String(), nil
 }
