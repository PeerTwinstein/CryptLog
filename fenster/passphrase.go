package fenster

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"io"

	"cryptlog/crypt"
	"golang.org/x/crypto/argon2"
)

// Kosten sind die Argon2id-Parameter, mit denen die Schlüsseldatei entsteht.
// Die Null ist der Ausgang: drei Durchgänge, 64 MiB, ein Thread.
type Kosten struct {
	Passes  uint32
	Memory  uint32
	Threads uint8
}

var (
	oidPBES2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidArgon2id  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11, 3}
	oidAES256GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}
)

type algorithm struct {
	OID    asn1.ObjectIdentifier
	Params asn1.RawValue
}

type pbes2 struct {
	KDF algorithm
	Enc algorithm
}

type argonBody struct {
	Salt    []byte
	Passes  int
	Memory  int
	Threads int
	KeyLen  int
}

type gcmBody struct {
	Nonce []byte
}

type encryptedKey struct {
	Algo algorithm
	Data []byte
}

// Verschluesseln legt einen privaten Schlüssel als EncryptedPrivateKeyInfo ab.
// PBES2, Argon2id, AES-256-GCM. Die Passphrase wird nicht behalten.
func Verschluesseln(rnd io.Reader, key crypto.PrivateKey, passphrase []byte, k Kosten) ([]byte, error) {
	defer crypt.Wipe(passphrase)
	if rnd == nil {
		rnd = rand.Reader
	}
	if len(passphrase) == 0 {
		return nil, ErrPassphrase
	}
	k = kosten(k)
	if k.Passes == 0 || k.Threads == 0 || k.Memory < uint32(k.Threads)*8 {
		return nil, ErrPassphrase
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	defer crypt.Wipe(der)
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err = io.ReadFull(rnd, salt); err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(rnd, nonce); err != nil {
		return nil, err
	}
	abgeleitet := argon2.IDKey(passphrase, salt, k.Passes, k.Memory, k.Threads, 32)
	defer crypt.Wipe(abgeleitet)
	block, err := aes.NewCipher(abgeleitet)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	geheim := gcm.Seal(nil, nonce, der, nil)
	defer crypt.Wipe(geheim)
	kdf, err := algo(oidArgon2id, argonBody{Salt: salt, Passes: int(k.Passes), Memory: int(k.Memory), Threads: int(k.Threads), KeyLen: 32})
	if err != nil {
		return nil, err
	}
	enc, err := algo(oidAES256GCM, gcmBody{Nonce: nonce})
	if err != nil {
		return nil, err
	}
	params, err := asn1.Marshal(pbes2{KDF: kdf, Enc: enc})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(encryptedKey{
		Algo: algorithm{OID: oidPBES2, Params: asn1.RawValue{FullBytes: params}},
		Data: append([]byte(nil), geheim...),
	})
}

// Entschluesseln öffnet eine EncryptedPrivateKeyInfo. Klartext-PKCS#8 lehnt es ab.
func Entschluesseln(der, passphrase []byte) (crypto.PrivateKey, error) {
	der = pemOderDER(der)
	if len(passphrase) == 0 || len(der) == 0 {
		return nil, ErrPassphrase
	}
	if _, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return nil, ErrPassphrase
	}
	var info encryptedKey
	rest, err := asn1.Unmarshal(der, &info)
	if err != nil || len(rest) != 0 || !info.Algo.OID.Equal(oidPBES2) {
		return nil, ErrPassphrase
	}
	var params pbes2
	rest, err = asn1.Unmarshal(info.Algo.Params.FullBytes, &params)
	if err != nil || len(rest) != 0 || !params.KDF.OID.Equal(oidArgon2id) || !params.Enc.OID.Equal(oidAES256GCM) {
		return nil, ErrPassphrase
	}
	var argon argonBody
	rest, err = asn1.Unmarshal(params.KDF.Params.FullBytes, &argon)
	if err != nil || len(rest) != 0 || argon.KeyLen != 32 || argon.Passes < 1 || argon.Threads < 1 || argon.Memory < argon.Threads*8 || len(argon.Salt) < 8 {
		return nil, ErrPassphrase
	}
	var gcmParams gcmBody
	rest, err = asn1.Unmarshal(params.Enc.Params.FullBytes, &gcmParams)
	if err != nil || len(rest) != 0 || len(gcmParams.Nonce) != 12 {
		return nil, ErrPassphrase
	}
	abgeleitet := argon2.IDKey(passphrase, argon.Salt, uint32(argon.Passes), uint32(argon.Memory), uint8(argon.Threads), 32)
	defer crypt.Wipe(abgeleitet)
	block, err := aes.NewCipher(abgeleitet)
	if err != nil {
		return nil, ErrPassphrase
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrPassphrase
	}
	klar, err := gcm.Open(nil, gcmParams.Nonce, info.Data, nil)
	if err != nil {
		return nil, ErrPassphrase
	}
	defer crypt.Wipe(klar)
	return x509.ParsePKCS8PrivateKey(klar)
}

func kosten(k Kosten) Kosten {
	if k.Passes == 0 && k.Memory == 0 && k.Threads == 0 {
		return Kosten{Passes: 3, Memory: 64 * 1024, Threads: 1}
	}
	return k
}

func algo(oid asn1.ObjectIdentifier, body any) (algorithm, error) {
	raw, err := asn1.Marshal(body)
	if err != nil {
		return algorithm{}, err
	}
	return algorithm{OID: oid, Params: asn1.RawValue{FullBytes: raw}}, nil
}

func pemOderDER(b []byte) []byte {
	if len(b) > 10 && b[0] == '-' {
		block, rest := pem.Decode(b)
		if block == nil || len(rest) != 0 || block.Type != "ENCRYPTED PRIVATE KEY" {
			return nil
		}
		return block.Bytes
	}
	return b
}
