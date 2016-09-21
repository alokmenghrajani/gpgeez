package gpgeez

import (
  "bytes"
  "golang.org/x/crypto/openpgp"
  "golang.org/x/crypto/openpgp/armor"
  "golang.org/x/crypto/openpgp/packet"
)

type Config struct {
  packet.Config
  Expiry uint32 // in days
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
 * CreateKey create a GPG key which is similar to what you get if you run GnuPG's
 * gpg --gen-key command line tool.
 *
 * You get back a primary signing key, an encryption subkey and self-signatures.
 *
 * This function sets expiry, preferred ciphers, etc.
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
 * Some useful links:
 * https://davesteele.github.io/gpg/2014/09/20/anatomy-of-a-gpg-key/
 */
func CreateKey(name, comment, email string, config *Config) (*Key, error) {
  // Create the key
  key, err := openpgp.NewEntity(name, comment, email, nil)
  if err != nil {
    return nil, err
  }

  // Self-sign the identity. Set expiry and algorithms
  dur := uint32(config.Expiry)
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

    err := id.SelfSignature.SignUserId(id.UserId.Id, key.PrimaryKey, key.PrivateKey, nil)
    if err != nil {
      return nil, err
    }
  }

  // Self-sign the Subkeys
  for _, subkey := range key.Subkeys {
    subkey.Sig.KeyLifetimeSecs = &dur
    err := subkey.Sig.SignKey(subkey.PublicKey, key.PrivateKey, nil)
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
