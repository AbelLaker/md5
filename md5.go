// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate go run gen.go -output md5block.go

// Package md5 implements the MD5 hash algorithm as defined in RFC 1321.
//
// MD5 is cryptographically broken and should not be used for secure
// applications.
package md5

import (
	"crypto"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash"
)

func init() {
	crypto.RegisterHash(crypto.MD5, New)
}

// The size of an MD5 checksum in bytes.
const Size = 16

// The blocksize of MD5 in bytes.
const BlockSize = 64

const (
	init0 = 0x67452301
	init1 = 0xEFCDAB89
	init2 = 0x98BADCFE
	init3 = 0x10325476
)

// digest represents the partial evaluation of a checksum.
type Digest struct {
	S   [4]uint32
	X   [BlockSize]byte
	Nx  int
	Len uint64
}

func (d *Digest) Reset() {
	d.S[0] = init0
	d.S[1] = init1
	d.S[2] = init2
	d.S[3] = init3
	d.Nx = 0
	d.Len = 0
}

const (
	magic         = "md5\x01"
	marshaledSize = len(magic) + 4*4 + BlockSize + 8
)

func (d *Digest) MarshalBinary() ([]byte, error) {
	b := make([]byte, 0, marshaledSize)
	b = append(b, magic...)
	b = appendUint32(b, d.S[0])
	b = appendUint32(b, d.S[1])
	b = appendUint32(b, d.S[2])
	b = appendUint32(b, d.S[3])
	b = append(b, d.X[:d.Nx]...)
	b = b[:len(b)+len(d.X)-d.Nx] // already zero
	b = appendUint64(b, d.Len)
	return b, nil
}

func (d *Digest) UnmarshalBinary(b []byte) error {
	if len(b) < len(magic) || string(b[:len(magic)]) != magic {
		return errors.New("crypto/md5: invalid hash state identifier")
	}
	if len(b) != marshaledSize {
		return errors.New("crypto/md5: invalid hash state size")
	}
	b = b[len(magic):]
	b, d.S[0] = consumeUint32(b)
	b, d.S[1] = consumeUint32(b)
	b, d.S[2] = consumeUint32(b)
	b, d.S[3] = consumeUint32(b)
	b = b[copy(d.X[:], b):]
	b, d.Len = consumeUint64(b)
	d.Nx = int(d.Len % BlockSize)
	return nil
}

func appendUint64(b []byte, x uint64) []byte {
	var a [8]byte
	binary.BigEndian.PutUint64(a[:], x)
	return append(b, a[:]...)
}

func appendUint32(b []byte, x uint32) []byte {
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], x)
	return append(b, a[:]...)
}

func consumeUint64(b []byte) ([]byte, uint64) {
	return b[8:], binary.BigEndian.Uint64(b[0:8])
}

func consumeUint32(b []byte) ([]byte, uint32) {
	return b[4:], binary.BigEndian.Uint32(b[0:4])
}

// New returns a new hash.Hash computing the MD5 checksum. The Hash also
// implements encoding.BinaryMarshaler and encoding.BinaryUnmarshaler to
// marshal and unmarshal the internal state of the hash.
func New() hash.Hash {
	d := new(Digest)
	d.Reset()
	return d
}

func NewByJason(r string) hash.Hash {
	d := new(Digest)
	err := json.Unmarshal([]byte(r), d)
	if err != nil {
		d.Reset()
	}
	return d
}

func (d *Digest) Size() int { return Size }

func (d *Digest) BlockSize() int { return BlockSize }

func (d *Digest) Write(p []byte) (nn int, err error) {
	// Note that we currently call block or blockGeneric
	// directly (guarded using haveAsm) because this allows
	// escape analysis to see that p and d don't escape.
	nn = len(p)
	d.Len += uint64(nn)
	if d.Nx > 0 {
		n := copy(d.X[d.Nx:], p)
		d.Nx += n
		if d.Nx == BlockSize {
			if haveAsm {
				block(d, d.X[:])
			} else {
				blockGeneric(d, d.X[:])
			}
			d.Nx = 0
		}
		p = p[n:]
	}
	if len(p) >= BlockSize {
		n := len(p) &^ (BlockSize - 1)
		if haveAsm {
			block(d, p[:n])
		} else {
			blockGeneric(d, p[:n])
		}
		p = p[n:]
	}
	if len(p) > 0 {
		d.Nx = copy(d.X[:], p)
	}
	return
}

func (d *Digest) Sum(in []byte) []byte {
	// Make a copy of d so that caller can keep writing and summing.
	d0 := *d
	hash := d0.checkSum()
	return append(in, hash[:]...)
}

func (d *Digest) checkSum() [Size]byte {
	// Append 0x80 to the end of the message and then append zeros
	// until the length is a multiple of 56 bytes. Finally append
	// 8 bytes representing the message length in bits.
	//
	// 1 byte end marker :: 0-63 padding bytes :: 8 byte length
	tmp := [1 + 63 + 8]byte{0x80}
	pad := (55 - d.Len) % 64                             // calculate number of padding bytes
	binary.LittleEndian.PutUint64(tmp[1+pad:], d.Len<<3) // append length in bits
	d.Write(tmp[:1+pad+8])

	// The previous write ensures that a whole number of
	// blocks (i.e. a multiple of 64 bytes) have been hashed.
	if d.Nx != 0 {
		panic("d.nx != 0")
	}

	var Digest [Size]byte
	binary.LittleEndian.PutUint32(Digest[0:], d.S[0])
	binary.LittleEndian.PutUint32(Digest[4:], d.S[1])
	binary.LittleEndian.PutUint32(Digest[8:], d.S[2])
	binary.LittleEndian.PutUint32(Digest[12:], d.S[3])
	return Digest
}

// Sum returns the MD5 checksum of the data.
func Sum(data []byte) [Size]byte {
	var d Digest
	d.Reset()
	d.Write(data)
	return d.checkSum()
}
