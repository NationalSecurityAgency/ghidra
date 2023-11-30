/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
  This file attempts to touch all functions in all built-in golang modules so
  that the resulting binary will contain a full snapshot, via DWARF, of all
  golang functions and their parameter information.
  Care must be taken to ensure that invalid parameter arguments do not cause a
  static exception that allows the golang compiler to elide the call and
  portions of the caller function.
*/

package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/flate"
	"compress/gzip"
	"compress/lzw"
	"compress/zlib"
	"container/heap"
	"container/list"
	"container/ring"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"debug/buildinfo"
	"debug/elf"
	"debug/gosym"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	//"log/syslog" // needs to be commented out for windows builds
	"math"
	"math/big"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"plugin"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/scanner"
	"text/tabwriter"
	"text/template"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
	//"unsafe" // does not produce function signatures that can be captured
)

//go:noinline
func archivePackage() {
	archiveTarPackage()
	archiveZipPackage()
}

//go:noinline
func archiveTarPackage() {
	header, _ := tar.FileInfoHeader(nil, "link")
	header.FileInfo()

	reader := tar.NewReader(nil)
	reader.Next()

	b := make([]byte, 100)
	reader.Read(nil)

	writer := tar.NewWriter(nil)
	writer.Close()
	writer.Flush()
	writer.Write(b)
	writer.WriteHeader(nil)

	fmt.Println("end of archive/tar")
}

//go:noinline
func archiveZipPackage() {
	zip.RegisterCompressor(0, nil)
	zip.RegisterDecompressor(0, nil)

	var file *zip.File
	file.DataOffset()
	file.Open()
	file.OpenRaw()

	fh, _ := zip.FileInfoHeader(nil)

	fh.FileInfo()
	fh.ModTime()
	fh.Mode()
	fh.SetModTime(time.Now())
	fh.SetMode(0)

	rc, _ := zip.OpenReader("name")
	rc.Close()

	reader, _ := zip.NewReader(nil, 0)
	reader.Open("name")
	reader.RegisterDecompressor(0, nil)

	writer := zip.NewWriter(nil)
	writer.Close()
	writer.Copy(nil)
	writer.Create("name")
	writer.CreateHeader(nil)
	writer.CreateRaw(nil)
	writer.Flush()
	writer.RegisterCompressor(0, nil)
	writer.SetComment("string")
	writer.SetOffset(0)

	fmt.Println("end of archive/zip")
}

//go:noinline
func bufioPackage() {
	b := make([]byte, 100)

	bufio.ScanBytes(nil, true)
	bufio.ScanLines(nil, true)
	bufio.ScanRunes(nil, true)
	bufio.ScanWords(nil, true)
	bufio.NewReadWriter(nil, nil)
	reader := bufio.NewReader(nil)
	bufio.NewReaderSize(nil, 0)
	reader.Buffered()
	reader.Discard(0)
	reader.Peek(0)
	reader.Read(b)
	reader.ReadByte()
	reader.ReadBytes(0)
	reader.ReadLine()
	reader.ReadRune()
	reader.ReadSlice(0)
	reader.ReadString(0)
	reader.Reset(nil)
	reader.Size()
	reader.UnreadByte()
	reader.UnreadRune()
	reader.WriteTo(nil)

	scanner := bufio.NewScanner(nil)
	scanner.Buffer(nil, 0)
	scanner.Bytes()
	scanner.Err()
	scanner.Scan()
	scanner.Split(nil)
	scanner.Text()

	writer := bufio.NewWriter(nil)
	bufio.NewWriterSize(nil, 0)
	writer.Available()
	writer.AvailableBuffer()
	writer.Buffered()
	writer.Flush()
	writer.ReadFrom(nil)
	writer.Reset(nil)
	writer.Size()
	writer.Write(nil)
	writer.WriteByte(0)
	writer.WriteRune(0)
	writer.WriteString("string")

	fmt.Println("end of bufio")
}

//go:noinline
func bytesPackage() {
	bytes.Clone(nil)
	bytes.Compare(nil, nil)
	bytes.Contains(nil, nil)
	bytes.ContainsAny(nil, "chars")
	bytes.ContainsRune(nil, 0)
	bytes.Count(nil, nil)
	bytes.Cut(nil, nil)
	bytes.CutPrefix(nil, nil)
	bytes.CutSuffix(nil, nil)
	bytes.Equal(nil, nil)
	bytes.EqualFold(nil, nil)
	bytes.Fields(nil)
	bytes.FieldsFunc(nil, nil)
	bytes.HasPrefix(nil, nil)
	bytes.HasSuffix(nil, nil)
	bytes.Index(nil, nil)
	bytes.IndexAny(nil, "chars")
	bytes.IndexByte(nil, 0)
	bytes.IndexFunc(nil, nil)
	bytes.IndexRune(nil, 0)
	bytes.Join(nil, nil)
	bytes.LastIndex(nil, nil)
	bytes.LastIndexAny(nil, "chars")
	bytes.LastIndexByte(nil, 0)
	bytes.LastIndexFunc(nil, nil)
	bytes.Map(nil, nil)
	bytes.Repeat(nil, 0)
	bytes.Replace(nil, nil, nil, 0)
	bytes.ReplaceAll(nil, nil, nil)
	bytes.Runes(nil)
	bytes.Split(nil, nil)
	bytes.SplitAfter(nil, nil)
	bytes.SplitAfterN(nil, nil, 0)
	bytes.SplitN(nil, nil, 0)
	bytes.Title(nil)
	bytes.ToLower(nil)
	bytes.ToLowerSpecial(nil, nil)
	bytes.ToTitle(nil)
	bytes.ToTitleSpecial(nil, nil)
	bytes.ToUpper(nil)
	bytes.ToUpperSpecial(nil, nil)
	bytes.ToValidUTF8(nil, nil)
	bytes.Trim(nil, "string")
	bytes.TrimFunc(nil, nil)
	bytes.TrimLeft(nil, "string")
	bytes.TrimLeftFunc(nil, nil)
	bytes.TrimPrefix(nil, nil)
	bytes.TrimRight(nil, "string")
	bytes.TrimRightFunc(nil, nil)
	bytes.TrimSpace(nil)
	bytes.TrimSuffix(nil, nil)
	buf := bytes.NewBuffer(nil)
	bytes.NewBufferString("string")
	buf.Bytes()
	buf.Cap()
	buf.Grow(0)
	buf.Len()
	buf.Next(0)
	buf.Read(nil)
	buf.ReadByte()
	buf.ReadBytes(0)
	buf.ReadFrom(nil)
	buf.ReadRune()
	buf.ReadString(0)
	buf.Reset()
	buf.String()
	buf.Truncate(0)
	buf.UnreadByte()
	buf.UnreadRune()
	buf.Write(nil)
	buf.WriteByte(0)
	buf.WriteRune(0)
	buf.WriteString("string")
	buf.WriteTo(nil)
	reader := bytes.NewReader(nil)
	reader.Len()
	reader.Read(nil)
	reader.ReadAt(nil, 0)
	reader.ReadByte()
	reader.ReadRune()
	reader.Reset(nil)
	reader.Seek(0, 0)
	reader.Size()
	reader.UnreadByte()
	reader.UnreadRune()
	reader.WriteTo(nil)

	fmt.Println("end of bytes")
}

//go:noinline
func compressPackage() {
	compressGzipPackage()
	compressBzip2Package()
	compressFlatePackage()
	compressLzwPackage()
	compressZlibPackage()
}

//go:noinline
func compressGzipPackage() {
	reader, _ := gzip.NewReader(nil)
	reader.Close()
	reader.Multistream(true)
	reader.Read(nil)
	reader.Reset(nil)

	writer := gzip.NewWriter(nil)
	gzip.NewWriterLevel(nil, 0)
	writer.Close()
	writer.Flush()
	writer.Reset(nil)
	writer.Write(nil)

	fmt.Println("end of compress/gzip")
}

//go:noinline
func compressBzip2Package() {
	bzip2.NewReader(nil)

	fmt.Println("end of compress/bzip2")
}

//go:noinline
func compressFlatePackage() {
	flate.NewReader(nil)
	flate.NewReaderDict(nil, nil)
	writer, _ := flate.NewWriter(nil, 0)
	flate.NewWriterDict(nil, 0, nil)
	writer.Close()
	writer.Flush()
	writer.Reset(nil)
	writer.Write(nil)

	fmt.Println("end of compress/flate")
}

//go:noinline
func compressLzwPackage() {
	reader := lzw.NewReader(nil, 0, 0)
	writer := lzw.NewWriter(nil, 0, 0)

	reader.Close()
	reader.Read(nil)
	var r *lzw.Reader
	r.Reset(nil, 0, 0)

	writer.Close()
	var w *lzw.Writer
	w.Reset(nil, 0, 0)
	writer.Write(nil)

	fmt.Println("end of compress/lzw")
}

//go:noinline
func compressZlibPackage() {
	zlib.NewReader(nil)
	zlib.NewReaderDict(nil, nil)

	writer := zlib.NewWriter(nil)
	zlib.NewWriterLevel(nil, 0)
	zlib.NewWriterLevelDict(nil, 0, nil)
	writer.Close()
	writer.Flush()
	writer.Reset(nil)
	writer.Write(nil)

	fmt.Println("end of compress/zlib")
}

//go:noinline
func containerPackage() {
	containerHeapPackage()
	containerListPackage()
	containerRingPackage()
}

//go:noinline
func containerHeapPackage() {
	heap.Fix(nil, 0)
	heap.Init(nil)
	heap.Pop(nil)
	heap.Push(nil, 0)
	heap.Remove(nil, 0)

	fmt.Println("end of container/heap")
}

//go:noinline
func containerListPackage() {
	l := list.New()
	l.Back()
	l.Front()
	l.Init()
	l.InsertAfter(nil, nil)
	l.InsertBefore(nil, nil)
	l.Len()
	l.MoveAfter(nil, nil)
	l.MoveBefore(nil, nil)
	l.MoveToBack(nil)
	l.MoveToFront(nil)
	l.PushBack(nil)
	l.PushBackList(nil)
	l.PushFront(nil)
	l.PushFrontList(nil)
	l.Remove(nil)

	fmt.Println("end of container/list")
}

//go:noinline
func containerRingPackage() {
	r := ring.New(0)
	r.Do(nil)
	r.Len()
	r.Link(nil)
	r.Move(0)
	r.Next()
	r.Prev()
	r.Unlink(0)

	fmt.Println("end of container/ring")
}

//go:noinline
func contextPackage() {
	c := context.Background()
	context.TODO()
	context.WithValue(c, nil, nil)

	context.Cause(c)
	context.WithCancel(c)
	context.WithCancelCause(c)
	context.WithDeadline(c, time.Now())
	context.WithTimeout(c, 0)

	fmt.Println("end of context")
}

//go:noinline
func cryptoPackage() {
	//crypto.RegisterHash(0, nil)
	var h crypto.Hash = 1
	h.Available()
	h.HashFunc()
	h.New()
	h.Size()
	h.String()

	cryptoAesPackage()
	cryptoCipherPackage()
	cryptoDesPackage()
	cryptoDsaPackage()
	cryptoEcdhPackage()
	cryptoEcdsaPackage()
	cryptoEd25519Package()
	cryptoEllipticPackage()
	cryptoHmacPackage()
	cryptoMd5Package()
	cryptoRandPackage()
	cryptoRc4Package()
	cryptoRsaPackage()
	cryptoSha1Package()
	cryptoSha256Package()
	cryptoSha512Package()
	cryptoSubtlePackage()
	cryptoTlsPackage()
	cryptoX509Package()

	fmt.Println("end of crypto package")
}

//go:noinline
func cryptoAesPackage() {
	aes.NewCipher(nil)
	fmt.Println("end of crypto/aes")
}

//go:noinline
func cryptoCipherPackage() {
	cipher.NewGCM(nil)
	cipher.NewGCMWithNonceSize(nil, 0)
	cipher.NewGCMWithTagSize(nil, 0)

	cipher.NewCBCDecrypter(nil, nil)
	cipher.NewCBCEncrypter(nil, nil)

	cipher.NewCFBDecrypter(nil, nil)
	cipher.NewCFBEncrypter(nil, nil)
	cipher.NewCTR(nil, nil)
	cipher.NewOFB(nil, nil)

	var sr cipher.StreamReader
	sr.Read(nil)
	var sw cipher.StreamWriter
	sw.Close()
	sw.Write(nil)
	fmt.Println("end of crypto/cipher")
}

//go:noinline
func cryptoDesPackage() {
	des.NewCipher(nil)
	des.NewTripleDESCipher(nil)
	fmt.Println("end of crypto/des")
}

//go:noinline
func cryptoDsaPackage() {
	dsa.GenerateKey(nil, nil)
	dsa.GenerateParameters(nil, nil, 0)
	dsa.Sign(nil, nil, nil)
	dsa.Verify(nil, nil, nil, nil)
	fmt.Println("end of crypto/dsa")
}

//go:noinline
func cryptoEcdhPackage() {
	ecdh.P256()
	ecdh.P384()
	ecdh.P521()
	ecdh.X25519()

	var pk *ecdh.PrivateKey
	pk.Bytes()
	pk.ECDH(nil)
	pk.Equal(nil)
	pk.Public()
	pk.PublicKey()

	var pubk *ecdh.PublicKey
	pubk.Bytes()
	pubk.Curve()
	pubk.Equal(nil)
	fmt.Println("end of crypto/ecdh")
}

//go:noinline
func cryptoEcdsaPackage() {
	ecdsa.Sign(nil, nil, nil)
	ecdsa.SignASN1(nil, nil, nil)
	ecdsa.Verify(nil, nil, nil, nil)
	ecdsa.VerifyASN1(nil, nil, nil)

	var pk2 *ecdsa.PrivateKey
	ecdsa.GenerateKey(nil, nil)
	pk2.ECDH()
	pk2.Equal(nil)
	pk2.Public()
	pk2.Sign(nil, nil, nil)

	var pubk2 *ecdsa.PublicKey
	pubk2.ECDH()
	pubk2.Equal(nil)
	fmt.Println("end of crypto/ecdsa")
}

//go:noinline
func cryptoEd25519Package() {

	ed25519.GenerateKey(nil)
	ed25519.Sign(nil, nil)
	ed25519.Verify(nil, nil, nil)
	ed25519.VerifyWithOptions(nil, nil, nil, nil)
	pk3 := ed25519.NewKeyFromSeed(nil)
	pk3.Equal(nil)
	pk3.Public()
	pk3.Seed()
	pk3.Sign(nil, nil, nil)

	var pubk3 *ed25519.PublicKey
	pubk3.Equal(nil)
	fmt.Println("end of crypto/ed25519")
}

//go:noinline
func cryptoEllipticPackage() {
	elliptic.GenerateKey(nil, nil)
	elliptic.Marshal(nil, nil, nil)
	elliptic.MarshalCompressed(nil, nil, nil)
	elliptic.Unmarshal(nil, nil)
	elliptic.UnmarshalCompressed(nil, nil)
	elliptic.P224()
	elliptic.P256()
	elliptic.P384()
	elliptic.P521()

	var cp *elliptic.CurveParams
	cp.Add(nil, nil, nil, nil)
	cp.Double(nil, nil)
	cp.IsOnCurve(nil, nil)
	cp.Params()
	cp.ScalarBaseMult(nil)
	cp.ScalarMult(nil, nil, nil)
	fmt.Println("end of crypto/elliptic")
}

//go:noinline
func cryptoHmacPackage() {
	hmac.Equal(nil, nil)
	hmac.New(nil, nil)
	fmt.Println("end of crypto/hmac")
}

//go:noinline
func cryptoMd5Package() {
	md5.New()
	md5.Sum(nil)
	fmt.Println("end of crypto/md5")
}

//go:noinline
func cryptoRandPackage() {
	rand.Int(nil, nil)
	rand.Prime(nil, 0)
	rand.Read(nil)
	fmt.Println("end of crypto/rand")
}

//go:noinline
func cryptoRc4Package() {
	rc4cipher, _ := rc4.NewCipher(nil)
	rc4cipher.Reset()
	rc4cipher.XORKeyStream(nil, nil)
	fmt.Println("end of crypto/rc4")
}

//go:noinline
func cryptoRsaPackage() {

	rsa.DecryptOAEP(nil, nil, nil, nil, nil)
	rsa.DecryptPKCS1v15(nil, nil, nil)
	rsa.DecryptPKCS1v15SessionKey(nil, nil, nil, nil)
	rsa.EncryptOAEP(nil, nil, nil, nil, nil)
	rsa.EncryptPKCS1v15(nil, nil, nil)
	rsa.SignPKCS1v15(nil, nil, 0, nil)
	rsa.SignPSS(nil, nil, 0, nil, nil)
	rsa.VerifyPKCS1v15(nil, 0, nil, nil)
	rsa.VerifyPSS(nil, 0, nil, nil, nil)

	rsapk, _ := rsa.GenerateKey(nil, 0)
	rsa.GenerateMultiPrimeKey(nil, 0, 0)

	rsapk.Decrypt(nil, nil, nil)
	rsapk.Equal(nil)
	rsapk.Precompute()
	rsapk.Public()
	rsapk.Sign(nil, nil, nil)
	rsapk.Validate()

	var rsapub rsa.PublicKey
	rsapub.Equal(nil)
	rsapub.Size()
	fmt.Println("end of crypto/rsa")
}

//go:noinline
func cryptoSha1Package() {
	sha1.New()
	sha1.Sum(nil)

	fmt.Println("end of crypto/sha1")
}

//go:noinline
func cryptoSha256Package() {
	sha256.New()
	sha256.New224()
	sha256.Sum224(nil)
	sha256.Sum256(nil)

	fmt.Println("end of crypto/sha256")
}

//go:noinline
func cryptoSha512Package() {
	sha512.New()
	sha512.New384()
	sha512.New512_224()
	sha512.New512_256()
	sha512.Sum384(nil)
	sha512.Sum512(nil)
	sha512.Sum512_224(nil)
	sha512.Sum512_256(nil)

	fmt.Println("end of crypto/sha512")
}

//go:noinline
func cryptoSubtlePackage() {
	subtle.ConstantTimeByteEq(0, 0)
	subtle.ConstantTimeCompare(nil, nil)
	subtle.ConstantTimeCopy(0, nil, nil)
	subtle.ConstantTimeEq(0, 0)
	subtle.ConstantTimeLessOrEq(0, 0)
	subtle.ConstantTimeSelect(0, 0, 0)
	subtle.XORBytes(nil, nil, nil)

	fmt.Println("end of crypto/subtle")
}

//go:noinline
func cryptoTlsPackage() {
	tls.CipherSuiteName(0)
	tls.Listen("network", "laddr", nil)
	tls.NewListener(nil, nil)
	tls.LoadX509KeyPair("certfile", "keyfile")
	tls.X509KeyPair(nil, nil)
	var cri *tls.CertificateRequestInfo
	cri.Context()
	cri.SupportsCertificate(nil)

	tls.CipherSuites()
	tls.InsecureCipherSuites()

	var chi *tls.ClientHelloInfo
	chi.Context()
	chi.SupportsCertificate(nil)

	tls.NewLRUClientSessionCache(0)

	conn := tls.Client(nil, nil)
	tls.Dial("network", "addr", nil)
	tls.DialWithDialer(nil, "network", "addr", nil)
	tls.Server(nil, nil)
	conn.Close()
	conn.CloseWrite()
	conn.ConnectionState()
	conn.Handshake()
	conn.HandshakeContext(nil)
	conn.LocalAddr()
	conn.NetConn()
	conn.OCSPResponse()
	conn.Read(nil)
	conn.RemoteAddr()
	conn.SetDeadline(time.Now())
	conn.SetReadDeadline(time.Now())
	conn.SetWriteDeadline(time.Now())
	conn.VerifyHostname("host")
	conn.Write(nil)

	fmt.Println("end of crypto/tls")

}

//go:noinline
func cryptoX509Package() {
	x509.CreateCertificate(nil, nil, nil, nil, nil)
	x509.CreateCertificateRequest(nil, nil, nil)
	x509.CreateRevocationList(nil, nil, nil, nil)
	x509.MarshalECPrivateKey(nil)
	x509.MarshalPKCS1PrivateKey(nil)
	x509.MarshalPKCS1PublicKey(nil)
	x509.MarshalPKCS8PrivateKey(nil)
	x509.MarshalPKIXPublicKey(nil)
	x509.ParseECPrivateKey(nil)
	x509.ParsePKCS1PrivateKey(nil)
	x509.ParsePKCS1PublicKey(nil)
	x509.ParsePKCS8PrivateKey(nil)
	x509.ParsePKIXPublicKey(nil)
	x509.SetFallbackRoots(nil)
	certpool := x509.NewCertPool()
	x509.SystemCertPool()
	certpool.AddCert(nil)
	certpool.AppendCertsFromPEM(nil)
	certpool.Clone()
	certpool.Equal(nil)
	cert, _ := x509.ParseCertificate(nil)
	x509.ParseCertificates(nil)
	cert.CheckSignature(1, nil, nil)
	cert.CheckSignatureFrom(nil)
	cert.Equal(nil)
	cert.Verify(x509.VerifyOptions{})
	cert.VerifyHostname("h")
	cr, _ := x509.ParseCertificateRequest(nil)
	cr.CheckSignature()

	rl, _ := x509.ParseRevocationList(nil)
	rl.CheckSignatureFrom(nil)

	fmt.Println("end of crypto/x509")

}

//go:noinline
func databaseSqlPackage() {
	sql.Drivers()
	sql.Register("name", nil)
	// todo
}

//go:noinline
func debugPackage() {
	debugBuildinfoPackage()
	// todo: dwarf
	debugElfPackage()

}

//go:noinline
func debugBuildinfoPackage() {
	buildinfo.Read(nil)
	buildinfo.ReadFile("name")

	fmt.Println("end of debug/buildinfo")
}

//go:noinline
func debugElfPackage() {
	elf.NewFile(nil)
	f, _ := elf.Open("name")
	f.Close()
	// todo
}

//go:noinline
func debugGosymPackage() {
	gosym.NewLineTable(nil, 0)
	gosym.NewTable(nil, nil)
}

//go:noinline
func errorsPackage() {
	err := errors.New("text")

	errors.As(err, err)
	errors.Is(err, err)
	errors.Join(err, err)
	errors.Unwrap(err)

	fmt.Println("end of errors package")
}

//go:noinline
func flagPackage() {
	var b bool
	var dur time.Duration
	var f64 float64
	var i64 int64
	var i int
	var s string
	var ui64 uint64

	flag.Arg(0)
	flag.Args()
	flag.Bool("name", false, "usage")
	//flag.BoolFunc("name", "usage", func (s string) error { return nil } ) // added in 1.21
	flag.BoolVar(&b, "name", false, "usage")
	flag.Duration("name", 0, "usage")
	flag.DurationVar(&dur, "name", 0, "usage")
	flag.Float64("name", 0, "usage")
	flag.Float64Var(&f64, "name", 0, "usage")
	flag.Func("name", "usage", func(s string) error { return nil })
	flag.Int("name", 0, "usage")
	flag.Int64("name", 0, "usage")
	flag.Int64Var(&i64, "name", 0, "usage")
	flag.IntVar(&i, "name", 0, "usage")
	flag.NArg()
	flag.NFlag()
	flag.Parse()
	flag.Parsed()
	flag.PrintDefaults()
	flag.Set("name", "value")
	flag.String("name", "value", "usage")
	flag.StringVar(&s, "name", "value", "usage")

	var ip net.IP
	flag.TextVar(&ip, "name", net.IPv4(1, 1, 1, 1), "usage")

	flag.Uint("name", 0, "usage")
	flag.Uint64("name", 0, "usage")
	flag.Uint64Var(&ui64, "name", 0, "usage")
	flag.UnquoteUsage(flag.Lookup("name"))
	//flag.Var(value, "name", "usage")
	flag.Visit(func(f *flag.Flag) {})
	flag.VisitAll(func(f *flag.Flag) {})

	fs := flag.NewFlagSet("name", 0)
	fs.Parse([]string{})

	fmt.Println("end of flag package")
}

//go:noinline
func fmtPackage() {
	b := make([]byte, 100)

	fmt.Append(b, "string", 55, true)
	fmt.Appendf(b, "format %d", 55)
	fmt.Appendln(b, "string")

	fmt.Errorf("my error %d", 55)

	fmt.Fprint(os.Stdout, "string", 42)
	fmt.Fprintf(os.Stdout, "format %d", 42)
	fmt.Fprintln(os.Stdout, "string")

	var i int
	var s string
	fmt.Fscan(os.Stdin, &i, &s)
	fmt.Fscanf(os.Stdin, "%d %s", &i, &s)
	fmt.Fscanln(os.Stdin, &s)

	fmt.Print("string")
	fmt.Printf("format %d", 43)
	fmt.Println("string")

	fmt.Scan(&i, &s)
	fmt.Scanf("%d %s", &i, &s)
	fmt.Scanln(&i, &s)

	fmt.Sprintf("format %d", 44)
	fmt.Sprintln("string")

	fmt.Sscan("string", &s)
	fmt.Sscanf("string", "%s", &s)
	fmt.Sscanln("string", &s)

	fmt.Println("end of fmt")
}

func ioAllPackage() {
	ioPackage()
	ioFsPackage()
	ioIoutilPackage()

	fmt.Println("end of io all")
}

//go:noinline
func ioPackage() {
	b := make([]byte, 100)
	io.Copy(os.Stdout, os.Stdin)
	io.CopyBuffer(os.Stdout, os.Stdin, b)
	io.CopyN(os.Stdout, os.Stdin, 0)
	io.Pipe()
	io.ReadAll(os.Stdin)
	io.ReadAtLeast(os.Stdin, b, 0)
	io.ReadFull(os.Stdin, b)
	io.WriteString(os.Stdout, "s")
	file, _ := os.Create("filename")
	ow := io.NewOffsetWriter(file, 0)
	ow.Seek(0, 0)
	ow.Write(b)
	ow.WriteAt(b, 0)
	pr := io.PipeReader{}
	pr.Close()
	pr.CloseWithError(nil)
	pr.Read(b)
	pw := io.PipeWriter{}
	pw.Close()
	pw.CloseWithError(nil)
	pw.Write(b)
	rc := io.NopCloser(os.Stdin)
	rc.Close()
	rc.Read(b)
	io.LimitReader(os.Stdin, 0)
	io.MultiReader(os.Stdin, os.Stdin)
	io.TeeReader(os.Stdin, os.Stdout)
	sr := io.NewSectionReader(file, 0, 0)
	sr.Read(b)
	sr.ReadAt(b, 0)
	sr.Size()
	io.MultiWriter(os.Stdout)

	fmt.Println("end of io package")
}

//go:noinline
func ioIoutilPackage() {
	b := make([]byte, 100)

	ioutil.NopCloser(os.Stdin)
	ioutil.ReadAll(os.Stdin)
	ioutil.ReadDir("dirname")
	ioutil.ReadFile("filename")
	ioutil.TempDir("dir", "pattern")
	ioutil.TempFile("dir", "pattern")
	ioutil.WriteFile("filename", b, fs.ModeAppend)

	fmt.Println("end of io/ioutil package")
}

//go:noinline
func ioFsPackage() {
	filesys := os.DirFS("dir")

	fs.Glob(filesys, "pattern")
	fs.ReadFile(filesys, "name")
	fs.ValidPath("name")
	fs.WalkDir(filesys, "root", func(path string, d fs.DirEntry, err error) error { return nil })
	//fs.FileInfoToDirEntry( )
	fs.ReadDir(filesys, "name")
	fs.Sub(filesys, "dir")
	fi, _ := fs.Stat(filesys, "name")
	fi.Name()
	fi.Size()
	fi.Mode()
	fi.ModTime()
	fi.IsDir()
	fi.Sys()

	fmt.Println("end of io/fs package")
}

func logAllPackage() {
	logPackage()
	logSyslogPackage()

	fmt.Println("end of log all")
}

//go:noinline
func logPackage() {
	if mathrand.Int() == 0 {
		log.Fatal("string")
	}
	if mathrand.Int() == 0 {
		log.Fatalf("format %s", "args")
	}
	if mathrand.Int() == 0 {
		log.Fatalln("string")
	}
	log.Flags()
	log.Output(0, "string")
	if mathrand.Int() == 0 {
		log.Panic("string")
	}
	if mathrand.Int() == 0 {
		log.Panicf("format %s", "string")
	}
	if mathrand.Int() == 0 {
		log.Panicln("string")
	}
	log.Prefix()
	log.Print("string")
	log.Printf("format %s", "string")
	log.Println("string")
	log.SetFlags(0)
	log.SetOutput(os.Stdout)
	log.Writer()

	l := log.Default()
	log.New(os.Stdout, "prefix", 0)
	if mathrand.Int() == 0 {
		l.Fatal("string")
	}
	if mathrand.Int() == 0 {
		l.Fatalf("format %s", "string")
	}
	if mathrand.Int() == 0 {
		l.Fatalln("string")
	}
	if mathrand.Int() == 0 {
		l.Panic("string")
	}
	if mathrand.Int() == 0 {
		l.Panicf("format %s", "string")
	}
	if mathrand.Int() == 0 {
		l.Panicln("string")
	}
	l.Prefix()
	l.Print("string")
	l.Printf("format %s", "string")
	l.Println("string")
	l.SetFlags(0)
	l.SetOutput(os.Stdout)
	l.Writer()

	fmt.Println("end of log package")
}

// syslog package is not present when GOOS=windows
//
//go:noinline
func logSyslogPackage() {
	/*
		syslog.NewLogger(0, 0)
		syslog.Dial("network", "raddr", 0, "tag")
		l, _ := syslog.New(0, "tag")
		l.Alert("m")
		l.Close()
		l.Crit("m")
		l.Debug("m")
		l.Emerg("m")
		l.Err("m")
		l.Info("m")
		l.Notice("m")
		l.Warning("m")
		l.Write(make([]byte, 100))
	*/
	fmt.Println("end of log/syslog package")
}

//go:noinline
func mathAllPackage() {
	mathPackage()
	mathBigPackage()
	mathRandPackage()

	fmt.Println("end of math all")
}

//go:noinline
func mathPackage() {
	math.Abs(0)
	math.Acos(0)
	math.Acosh(0)
	math.Asin(0)
	math.Atan(0)
	math.Atan2(0, 0)
	math.Atanh(0)
	math.Cbrt(0)
	math.Ceil(0)
	math.Cos(0)
	math.Cosh(0)
	math.Dim(0, 0)
	math.Erf(0)
	math.Erfc(0)
	math.Erfcinv(0)
	math.Erfinv(0)
	math.Exp(0)
	math.Exp2(0)
	math.Expm1(0)
	math.FMA(0, 0, 0)
	math.Float32bits(0)
	math.Float32frombits(0)
	math.Float64bits(0)
	math.Float64frombits(0)
	math.Floor(0)
	math.Frexp(0)
	math.Gamma(0)
	math.Hypot(0, 0)
	math.Ilogb(0)
	math.IsInf(0, 1)
	math.IsNaN(0)
	math.J0(0)
	math.J1(0)
	math.Ldexp(0, 0)
	math.Lgamma(0)
	math.Log(0)
	math.Log10(0)
	math.Log1p(0)
	math.Log2(0)
	math.Logb(0)
	math.Max(0, 0)
	math.Min(0, 0)
	math.Mod(0, 1)
	math.Modf(0)
	math.NaN()
	math.Nextafter(0, 0)
	math.Nextafter32(0, 0)
	math.Pow(0, 0)
	math.Pow10(0)
	math.Remainder(0, 1)
	math.Round(0)
	math.RoundToEven(0)
	math.Signbit(0)
	math.Sin(0)
	math.Sincos(0)
	math.Sinh(0)
	math.Sqrt(0)
	math.Tan(0)
	math.Tanh(0)
	math.Trunc(0)
	math.Y0(0)
	math.Y1(0)
	math.Yn(0, 0)

	fmt.Println("end of math")
}

//go:noinline
func mathBigPackage() {
	b := make([]byte, 100)
	i := big.NewInt(0)
	big.Jacobi(i, i)
	f := big.NewFloat(0)
	big.ParseFloat("s", 0, 0, big.AwayFromZero)
	f.Abs(f)
	f.Acc()
	f.Add(f, f)
	f.Append(b, 0, 0)
	f.Cmp(f)
	f.Copy(f)
	f.Float32()
	f.Float64()
	f.Format(nil, 0)
	f.GobDecode(b)
	f.GobEncode()
	f.Int(i)
	f.Int64()
	f.IsInf()
	f.IsInf()
	f.MantExp(f)
	f.MarshalText()
	f.MinPrec()
	f.Mode()
	f.Mul(f, f)
	f.Neg(f)
	f.Parse("s", 0)
	f.Prec()
	f.Quo(f, f)
	f.Rat(big.NewRat(0, 0))
	f.Scan(nil, 0)
	f.Set(f)
	f.SetFloat64(0)
	f.SetInf(true)
	f.SetInt(i)
	f.SetInt64(0)
	f.SetMantExp(f, 0)
	f.SetMode(big.AwayFromZero)
	f.SetPrec(0)
	f.SetRat(big.NewRat(0, 0))
	f.SetString("s")
	f.SetUint64(0)
	f.Sign()
	f.Signbit()
	f.Sqrt(f)
	f.String()
	f.Sub(f, f)
	f.Text(0, 0)
	f.Uint64()
	f.UnmarshalText(b)

	i.Abs(i)
	i.Add(i, i)
	i.And(i, i)
	i.AndNot(i, i)
	i.Append(b, 0)
	i.Binomial(0, 0)
	i.Bit(0)
	i.BitLen()
	i.Bits()
	i.Bytes()
	i.Cmp(i)
	i.CmpAbs(i)
	i.Div(i, i)
	i.DivMod(i, i, i)
	i.Exp(i, i, i)
	i.FillBytes(b)
	i.Format(nil, 0)
	i.GCD(i, i, i, i)
	i.GobDecode(b)
	i.GobEncode()
	i.Int64()
	i.IsInt64()
	i.IsUint64()
	i.Lsh(i, 0)
	i.MarshalJSON()
	i.MarshalText()
	i.Mod(i, i)
	i.ModInverse(i, i)
	i.ModSqrt(i, i)
	i.Mul(i, i)
	i.MulRange(0, 0)
	i.Neg(i)
	i.Not(i)
	i.Or(i, i)
	i.ProbablyPrime(0)
	i.Quo(i, i)
	i.QuoRem(i, i, i)
	i.Rand(&mathrand.Rand{}, i)
	i.Rem(i, i)
	i.Rsh(i, 0)
	i.Scan(nil, 0)
	i.Set(i)
	i.SetBit(i, 0, 0)
	i.SetBits([]big.Word{})
	i.SetBytes(b)
	i.SetInt64(0)
	i.SetString("s", 0)
	i.SetUint64(0)
	i.Sign()
	i.Sqrt(i)
	i.String()
	i.Sub(i, i)
	i.Text(0)
	i.TrailingZeroBits()
	i.Uint64()
	i.UnmarshalJSON(b)
	i.UnmarshalText(b)
	i.Xor(i, i)

	r := big.NewRat(0, 0)
	r.Abs(r)
	r.Cmp(r)
	r.Denom()
	r.Float32()
	r.Float64()
	r.FloatString(0)
	r.GobDecode(b)
	r.GobEncode()
	r.Inv(r)
	r.IsInt()
	r.MarshalText()
	r.Mul(r, r)
	r.Neg(r)
	r.Num()
	r.Quo(r, r)
	r.RatString()
	r.Scan(nil, 0)
	r.Set(r)
	r.SetFloat64(0)
	r.SetFrac(i, i)
	r.SetFrac64(0, 0)
	r.SetInt(i)
	r.SetInt64(0)
	r.SetString("s")
	r.SetUint64(0)
	r.Sign()
	r.String()
	r.Sub(r, r)
	r.UnmarshalText(b)

	fmt.Println("end of math/big")
}

//go:noinline
func mathRandPackage() {
	mathrand.ExpFloat64()
	mathrand.Float32()
	mathrand.Float64()
	mathrand.Int()
	mathrand.Int31()
	mathrand.Int31n(0)
	mathrand.Int63()
	mathrand.Int63n(0)
	mathrand.Intn(0)
	mathrand.NormFloat64()
	mathrand.Perm(0)
	mathrand.Shuffle(0, func(i, j int) {})
	mathrand.Uint32()
	mathrand.Uint64()
	rnd := mathrand.New(mathrand.NewSource(0))
	rnd.ExpFloat64()
	rnd.Float32()
	rnd.Float64()
	rnd.Int()
	rnd.Int31()
	rnd.Int31n(0)
	rnd.Int63()
	rnd.Int63n(0)
	rnd.Intn(0)
	rnd.NormFloat64()
	rnd.Perm(0)
	rnd.Read(make([]byte, 100))
	rnd.Seed(0)
	rnd.Shuffle(0, func(i, j int) {})
	rnd.Uint32()
	rnd.Uint64()
	zipf := mathrand.NewZipf(rnd, 0, 0, 0)
	zipf.Uint64()

	fmt.Println("end of math/rand")
}

//go:noinline
func netAllPackage() {
	netPackage()
	netHttpPackage()
	netUrlPackage()
}

//go:noinline
func netPackage() {
	net.JoinHostPort("host", "port")
	net.LookupAddr("addr")
	net.LookupCNAME("host")
	net.LookupHost("host")
	net.LookupPort("network", "service")
	net.LookupTXT("name")
	net.ParseCIDR("s")
	net.Pipe()
	net.SplitHostPort("hostport")
	net.InterfaceAddrs()
	net.Dial("network", "address")
	net.DialTimeout("network", "address", 0)
	net.FileConn(nil)
	net.ResolveIPAddr("network", "address")
	net.DialIP("network", nil, nil)
	ipconn, _ := net.ListenIP("network", nil)
	ipconn.Close()
	ipconn.File()
	ipconn.LocalAddr()
	ipconn.Read(nil)
	ipconn.ReadFrom(nil)
	ipconn.ReadFromIP(nil)
	ipconn.ReadMsgIP(nil, nil)
	ipconn.RemoteAddr()
	ipconn.SetDeadline(time.Now())
	ipconn.SetReadBuffer(0)
	ipconn.SetReadDeadline(time.Now())
	ipconn.SetWriteBuffer(0)
	ipconn.SetWriteDeadline(time.Now())
	ipconn.SyscallConn()
	ipconn.Write(nil)
	ipconn.WriteMsgIP(nil, nil, nil)
	ipconn.WriteTo(nil, nil)
	ipconn.WriteToIP(nil, nil)
	net.CIDRMask(0, 0)
	net.IPv4Mask(0, 0, 0, 0)
	iface, _ := net.InterfaceByIndex(0)
	net.InterfaceByName("name")
	net.Interfaces()
	iface.Addrs()
	iface.MulticastAddrs()

	net.FileListener(nil)
	net.Listen("network", "address")
	net.LookupMX("name")
	net.LookupNS("name")
	net.FilePacketConn(nil)
	net.ListenPacket("network", "address")

	var res *net.Resolver
	res.LookupAddr(nil, "addr")
	res.LookupCNAME(nil, "host")
	res.LookupHost(nil, "host")
	res.LookupIP(nil, "network", "host")
	res.LookupIPAddr(nil, "host")

	net.LookupSRV("service", "proto", "name")
	net.ResolveTCPAddr("network", "address")
	//net.TCPAddrFromAddrPort( netip.AddrPort{})

	tcpconn, _ := net.DialTCP("network", nil, nil)
	tcpconn.Close()
	tcpconn.CloseRead()
	tcpconn.CloseWrite()
	tcpconn.File()
	tcpconn.LocalAddr()
	tcpconn.Read(nil)
	tcpconn.ReadFrom(nil)
	tcpconn.RemoteAddr()
	tcpconn.SetDeadline(time.Now())
	tcpconn.SetKeepAlive(true)
	tcpconn.SetKeepAlivePeriod(0)
	tcpconn.SetLinger(0)
	tcpconn.SetNoDelay(true)
	tcpconn.SetReadBuffer(0)
	tcpconn.SetReadDeadline(time.Now())
	tcpconn.SetWriteBuffer(0)
	tcpconn.SetWriteDeadline(time.Now())
	tcpconn.SyscallConn()
	tcpconn.Write(nil)

	tcplist, _ := net.ListenTCP("network", nil)
	tcplist.Accept()
	tcplist.Addr()
	tcplist.Close()
	tcplist.File()
	tcplist.SetDeadline(time.Now())
	tcplist.SyscallConn()

	net.ResolveUDPAddr("network", "address")
	//net.UDPAddrFromAddrPort()
	net.DialUDP("network", nil, nil)
	net.ListenMulticastUDP("network", nil, nil)
	net.ListenUDP("network", nil)

	net.ResolveUnixAddr("network", "address")
	net.DialUnix("network", nil, nil)
	net.ListenUnixgram("network", nil)
	net.ListenUnix("network", nil)

	fmt.Println("end of net")

}

//go:noinline
func netHttpPackage() {
	http.CanonicalHeaderKey("s")
	http.DetectContentType(nil)
	http.Error(nil, "error", 0)
	http.Handle("pattern", nil)
	http.HandleFunc("pattern", http.NotFound)
	http.ListenAndServe("addr", nil)
	http.ListenAndServeTLS("addr", "certfile", "keyfile", nil)
	http.MaxBytesReader(nil, nil, 0)
	http.NotFound(nil, nil)
	http.ParseHTTPVersion("vers")
	http.ParseTime("text")
	http.ProxyFromEnvironment(nil)
	http.ProxyURL(nil)
	http.Redirect(nil, nil, "url", 0)
	http.Serve(nil, nil)
	http.ServeContent(nil, nil, "name", time.Now(), nil)
	http.ServeFile(nil, nil, "name")
	http.ServeTLS(nil, nil, "certfile", "keyfile")
	http.SetCookie(nil, nil)
	http.StatusText(0)
	var client *http.Client
	client.CloseIdleConnections()
	client.Do(nil)
	client.Get("url")
	client.Head("url")
	client.Post("url", "contenttype", nil)
	client.PostForm("url", nil)
	var cookie *http.Cookie
	cookie.String()
	cookie.Valid()
	http.AllowQuerySemicolons(nil)
	http.FileServer(nil)
	http.MaxBytesHandler(nil, 0)
	http.NotFoundHandler()
	http.RedirectHandler("url", 0)
	http.StripPrefix("prefix", nil)
	http.TimeoutHandler(nil, 0, "msg")
	var header http.Header
	header.Add("key", "value")
	header.Clone()
	header.Del("key")
	header.Get("key")
	header.Set("key", "value")
	header.Values("key")
	header.Write(nil)
	header.WriteSubset(nil, nil)

	req, _ := http.NewRequest("method", "url", nil)
	http.NewRequestWithContext(nil, "method", "url", nil)
	http.ReadRequest(nil)
	req.AddCookie(nil)
	req.BasicAuth()
	req.Clone(nil)
	req.Context()
	req.Cookie("name")
	req.Cookies()
	req.FormFile("key")
	req.MultipartReader()
	req.ParseForm()
	req.ParseMultipartForm(0)
	req.PostFormValue("key")
	req.ProtoAtLeast(0, 0)
	req.Referer()
	req.SetBasicAuth("username", "password")
	req.UserAgent()
	req.WithContext(context.Background())
	req.Write(nil)
	req.WriteProxy(nil)
	res, _ := http.Get("url")
	http.Head("url")
	http.Post("url", "contenttype", nil)
	http.PostForm("url", nil)
	http.ReadResponse(nil, nil)
	res.Cookies()
	res.Location()
	res.ProtoAtLeast(0, 0)
	res.Write(nil)
	http.NewResponseController(nil)
	http.NewFileTransport(nil)
	http.NewServeMux()
	var srv *http.Server
	srv.Close()
	srv.ListenAndServe()
	srv.ListenAndServeTLS("certfile", "keyfile")
	srv.RegisterOnShutdown(nil)
	srv.Serve(nil)
	srv.ServeTLS(nil, "certfile", "keyfile")
	srv.SetKeepAlivesEnabled(true)
	srv.Shutdown(nil)

	var t *http.Transport
	t.Clone()
	t.CloseIdleConnections()
	t.RegisterProtocol("scheme", nil)
	t.RoundTrip(nil)

	fmt.Println("end of net/http")

}

//go:noinline
func netUrlPackage() {
	url.JoinPath("base", "elem")
	url.PathEscape("s")
	url.PathUnescape("s")
	url.QueryEscape("s")
	url.QueryUnescape("s")

	u, _ := url.Parse("s")
	url.ParseRequestURI("s")
	u.EscapedFragment()
	u.EscapedPath()
	u.Hostname()
	u.IsAbs()
	u.JoinPath("s")
	u.MarshalBinary()
	u.Parse("ref")
	u.Port()
	u.Query()
	u.Redacted()
	u.RequestURI()
	u.ResolveReference(u)
	u.String()
	u.UnmarshalBinary(nil)
	user := url.User("username")
	url.UserPassword("username", "password")
	user.Password()
	user.String()
	user.Username()
	vals, _ := url.ParseQuery("query")
	vals.Add("key", "value")
	vals.Del("key")
	vals.Encode()
	vals.Get("key")
	vals.Has("key")
	vals.Set("key", "value")

	fmt.Println("end of net/url")
}

//go:noinline
func osPackage() {
	var err error

	os.Chdir("path")
	os.Chmod("filename", 0)
	os.Chown("filename", 0, 0)
	os.Chtimes("filename", time.Now(), time.Now())
	os.Clearenv()
	os.DirFS("dir")
	os.Environ()
	os.Executable()
	os.Exit(1)
	os.Expand("string", nil)
	os.ExpandEnv("string")
	os.Getegid()
	os.Getenv("string")
	os.Geteuid()
	os.Getgid()
	os.Getgroups()
	os.Getpagesize()
	os.Getpid()
	os.Getppid()
	os.Getuid()
	os.Getwd()
	os.Hostname()
	os.IsExist(err)
	os.IsNotExist(err)
	os.IsPathSeparator(0)
	os.IsPermission(err)
	os.IsTimeout(err)
	os.Lchown("filename", 0, 0)
	os.Link("filename", "filename")
	os.LookupEnv("key")
	os.Mkdir("filename", 0)
	os.MkdirAll("filename", 0)
	os.MkdirTemp("filename", "pattern")
	os.NewSyscallError("string", err)
	os.Pipe()
	os.ReadFile("filename")
	os.Readlink("filename")
	os.Remove("filename")
	os.RemoveAll("path")
	os.Rename("filename", "filename")
	os.SameFile(nil, nil)
	os.Setenv("key", "value")
	os.Symlink("filename", "filename")
	os.TempDir()
	os.Truncate("filename", 0)
	os.Unsetenv("key")
	os.UserCacheDir()
	os.UserConfigDir()
	os.UserHomeDir()
	os.WriteFile("filename", nil, 0)

	os.ReadDir("dir")

	file, _ := os.Create("filename")
	os.CreateTemp("dir", "pattern")
	os.NewFile(0, "filename")
	os.Open("filename")
	os.OpenFile("filename", 1, 0)

	b := make([]byte, 100)

	file.Chdir()
	file.Chmod(0)
	file.Chown(0, 0)
	file.Close()
	file.Fd()
	file.Name()
	file.Read(b)
	file.ReadAt(b, 0)
	file.ReadDir(0)
	file.ReadFrom(nil)
	file.Readdir(0)
	file.Readdirnames(0)
	file.Seek(0, 0)
	file.SetDeadline(time.Now())
	file.SetReadDeadline(time.Now())
	file.SetWriteDeadline(time.Now())
	file.Stat()
	file.Sync()
	file.SyscallConn()
	file.Truncate(0)
	file.Write(b)
	file.WriteAt(b, 0)
	file.WriteString("string")

	os.Lstat("filename")
	os.Stat("filename")

	os.FindProcess(0)
	p, _ := os.StartProcess("name", []string{}, nil)

	p.Kill()
	p.Release()
	p.Signal(nil)
	ps, _ := p.Wait()

	ps.ExitCode()
	ps.Exited()
	ps.Pid()
	ps.String()
	ps.Success()
	ps.Sys()
	ps.SysUsage()
	ps.SystemTime()
	ps.UserTime()

	fmt.Println("end of os")
}

//go:noinline
func pathPackage() {
	path.Base("path")
	path.Clean("path")
	path.Dir("path")
	path.Ext("path")
	path.IsAbs("path")
	path.Join("path1", "path2")
	path.Match("pattern", "name")
	path.Split("path")

	fmt.Println("end of path")
}

//go:noinline
func pathFilepathPackage() {
	filepath.Abs("path")
	filepath.Base("path")
	filepath.Clean("path")
	filepath.Dir("path")
	filepath.EvalSymlinks("path")
	filepath.Ext("path")
	filepath.FromSlash("path")
	filepath.Glob("pattern")
	filepath.IsAbs("path")
	filepath.IsLocal("path")
	filepath.Join("path1", "path2")
	filepath.Match("pattern", "name")
	filepath.Rel("base", "targ")
	filepath.Split("path")
	filepath.SplitList("path")
	filepath.ToSlash("path")
	filepath.VolumeName("path")
	filepath.Walk("root", func(path string, info fs.FileInfo, err error) error { return nil })
	filepath.WalkDir("root", func(path string, d fs.DirEntry, err error) error { return nil })

	fmt.Println("end of path/filepath")
}

//go:noinline
func pluginPackage() {
	p, _ := plugin.Open("path")
	sym, _ := p.Lookup("sym")
	fmt.Printf("sym: %v\n", sym)

	fmt.Println("end of plugin")
}

//go:noinline
func runtimePackage() {
	runtime.BlockProfile(nil)
	runtime.Breakpoint()
	//runtime.CPUProfile()
	runtime.Caller(0)
	runtime.Callers(0, nil)
	runtime.GC()
	runtime.GOMAXPROCS(0)
	runtime.GOROOT()
	//runtime.Goexit()
	runtime.GoroutineProfile(nil)
	runtime.Gosched()
	runtime.KeepAlive(nil)
	runtime.LockOSThread()
	runtime.MemProfile(nil, true)
	runtime.MutexProfile(nil)
	runtime.NumCPU()
	runtime.NumCgoCall()
	runtime.NumGoroutine()
	runtime.ReadMemStats(nil)
	runtime.ReadTrace()
	runtime.SetBlockProfileRate(0)
	runtime.SetCPUProfileRate(0)
	runtime.SetCgoTraceback(0, nil, nil, nil)
	runtime.SetFinalizer(nil, nil)
	runtime.SetMutexProfileFraction(0)
	runtime.Stack(nil, true)
	runtime.StartTrace()
	runtime.StopTrace()
	runtime.ThreadCreateProfile(nil)
	runtime.UnlockOSThread()
	runtime.Version()

	f := runtime.FuncForPC(0)
	f.Entry()
	f.FileLine(0)
	f.Name()

	fmt.Println("end of runtime")

}

//go:noinline
func timePackage() {
	b := make([]byte, 100)

	fmt.Println(time.After(0))
	time.Sleep(0)
	fmt.Println(time.Tick(0))
	fmt.Println(time.ParseDuration("s"))
	fmt.Println(time.Since(time.Now()))
	d := time.Until(time.Now())
	d += d.Abs()
	fmt.Println(d.Hours())
	ms := d.Microseconds()
	ms += d.Milliseconds()
	ms += int64(d.Minutes())
	ms += d.Nanoseconds()
	ms += int64(d.Round(0))
	ms += int64(d.Seconds())
	fmt.Println(d.String())
	ms += int64(d.Truncate(0))
	fmt.Println(ms)

	loc := time.FixedZone("name", 0)
	time.LoadLocation("name")
	time.LoadLocationFromTZData("name", nil)
	fmt.Println(loc.String())
	t := time.NewTicker(0)
	t.Reset(0)
	t.Stop()
	fmt.Println(time.Date(0, 0, 0, 0, 0, 0, 0, nil))
	fmt.Println(time.Now())
	fmt.Println(time.Parse("layout", "value"))
	time.ParseInLocation("layout", "value", nil)
	time.Unix(0, 0)
	time.UnixMicro(0)
	tm := time.UnixMilli(0)
	tm.Add(0)
	tm.AddDate(0, 0, 0)
	tm.After(tm)
	tm.AppendFormat(nil, "layout")
	tm.Before(tm)
	tm.Clock()
	tm.Compare(tm)
	tm.Date()
	tm.Day()
	fmt.Println(tm.Equal(tm))
	fmt.Println(tm.Format("layout"))
	fmt.Println(tm.GoString())
	tm.GobDecode(b)
	tm.Hour()
	tm.ISOWeek()
	tm.In(time.Local)
	tm.IsDST()
	tm.IsZero()
	tm.Local()
	tm.Location()
	tm.MarshalBinary()
	tm.MarshalJSON()
	tm.MarshalText()
	tm.Minute()
	tm.Month()
	tm.Nanosecond()
	tm.Round(0)
	tm.Second()
	tm.String()
	tm.Sub(tm)
	tm.Truncate(0)
	tm.UTC()
	tm.Unix()
	tm.UnixMicro()
	tm.UnixMilli()
	tm.UnixNano()
	tm.UnmarshalBinary(b)
	tm.UnmarshalJSON(b)
	tm.UnmarshalText(b)
	tm.Weekday()
	tm.Year()
	tm.YearDay()
	tm.Zone()
	tm.ZoneBounds()
	time.AfterFunc(0, nil)
	tmr := time.NewTimer(0)
	tmr.Reset(0)
	tmr.Stop()

	fmt.Println("end of time")
}

//go:noinline
func textPackage() {
	textScannerPackage()
	textTabwriterPackage()
	textTemplatePackage()
}

//go:noinline
func textScannerPackage() {
	var s scanner.Scanner
	scanner.TokenString(0)
	s.Init(nil)
	s.Next()
	s.Peek()
	s.Pos()
	s.Scan()
	s.TokenText()

	fmt.Println("end of text/scanner")
}

//go:noinline
func textTabwriterPackage() {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 0, 0, 0)
	w.Flush()
	w.Init(os.Stdout, 0, 0, 0, 0, 0)
	w.Write(nil)

	fmt.Println("end of text/tabwriter")
}

//go:noinline
func textTemplatePackage() {
	template.HTMLEscape(os.Stdout, nil)
	template.HTMLEscapeString("s")
	template.HTMLEscaper("s")
	template.IsTrue("s")
	template.JSEscape(os.Stdout, nil)
	template.JSEscapeString("s")
	template.JSEscaper("s")
	template.URLQueryEscaper("s")
	t := template.Must(template.New("name"), nil)
	t.AddParseTree("name", nil)
	t.Clone()
	t.DefinedTemplates()
	t.Delims("left", "right")
	t.Execute(os.Stdout, "blah")
	t.ExecuteTemplate(os.Stdout, "name", "any")
	t.Funcs(template.FuncMap{})
	t.Lookup("name")
	t.Name()
	t.New("name")
	t.Option("opt1")
	t.Parse("test")
	t.ParseFS(nil, "pattern")
	t.ParseFiles("filename")
	t.ParseGlob("pattern")
	t.Templates()

	fmt.Println("end of text/template")

}

//go:noinline
func strconvPackage() {
	b := make([]byte, 1000)
	strconv.AppendBool(b, true)
	strconv.AppendFloat(b, 1.1, 0, 0, 0)
	strconv.AppendInt(b, 0, 0)
	strconv.AppendQuote(b, "s")
	strconv.AppendQuoteRune(b, 0)
	strconv.AppendQuoteRuneToASCII(b, 0)
	strconv.AppendQuoteRuneToGraphic(b, 0)
	strconv.AppendQuoteToASCII(b, "s")
	strconv.AppendQuoteToGraphic(b, "s")
	strconv.AppendUint(b, 0, 0)
	strconv.Atoi("s")
	strconv.CanBackquote("s")
	strconv.FormatBool(true)
	strconv.FormatComplex(complex(1, 1), 0, 0, 0)
	strconv.FormatFloat(1, 0, 0, 0)
	strconv.FormatInt(0, 0)
	strconv.FormatUint(0, 0)
	strconv.IsGraphic(0)
	strconv.IsPrint(0)
	strconv.Itoa(0)
	strconv.ParseBool("b")
	strconv.ParseComplex("s", 0)
	strconv.ParseInt("s", 0, 0)
	strconv.ParseUint("s", 0, 0)
	strconv.Quote("s")
	strconv.QuoteRune(0)
	strconv.QuoteRuneToASCII(0)
	strconv.QuoteRuneToGraphic(0)
	strconv.QuoteToASCII("s")
	strconv.QuoteToGraphic("s")
	strconv.Unquote("s")

	fmt.Println("end of strconv")
}

//go:noinline
func syncPackage() {
	cond := sync.NewCond(&sync.Mutex{})
	cond.Broadcast()
	cond.Signal()
	cond.Wait()
	m := sync.Map{}
	m.CompareAndDelete("key", "old")
	m.CompareAndSwap("key", "old", "new")
	m.Delete("key")
	m.Load("value")
	m.LoadAndDelete("key")
	m.LoadOrStore("key", "value")
	m.Range(nil)
	m.Store("key", "value")
	m.Swap("key", "value")

	mux := sync.Mutex{}
	mux.Lock()
	mux.TryLock()
	mux.Unlock()
	once := sync.Once{}
	once.Do(nil)

	pool := sync.Pool{}
	pool.Get()
	pool.Put("any")

	rwmux := sync.RWMutex{}
	rwmux.Lock()
	rwmux.RLock()
	rwmux.RLocker()
	rwmux.RUnlock()
	rwmux.TryLock()
	rwmux.TryRLock()
	rwmux.Unlock()
	wg := sync.WaitGroup{}
	wg.Add(0)
	wg.Done()
	wg.Wait()

	fmt.Println("end of sync")
}

//go:noinline
func stringsPackage() {
	strings.Clone("s")
	strings.Compare("a", "b")
	strings.Contains("s", "s")
	strings.ContainsAny("s", "chars")
	strings.ContainsRune("s", 0)
	strings.Count("s", "substr")
	strings.Cut("s", "sep")
	strings.CutPrefix("s", "prefix")
	strings.CutSuffix("s", "suffix")
	strings.EqualFold("s", "t")
	strings.Fields("s")
	strings.FieldsFunc("s", func(r rune) bool { return true })
	strings.HasPrefix("s", "prefix")
	strings.HasSuffix("s", "suffix")
	strings.Index("s", "substr")
	strings.IndexAny("s", "chars")
	strings.IndexFunc("s", func(r rune) bool { return true })
	strings.IndexRune("s", 0)
	strings.Join([]string{"s", "s"}, "sep")
	strings.LastIndex("s", "substr")
	strings.LastIndexAny("s", "chars")
	strings.LastIndexByte("s", 0)
	strings.LastIndexFunc("s", func(r rune) bool { return true })
	strings.Map(func(r rune) rune { return r }, "s")
	strings.Repeat("s", 0)
	strings.Replace("s", "old", "new", 0)
	strings.ReplaceAll("s", "old", "new")
	strings.Split("s", "sep")
	strings.SplitAfter("s", "sep")
	strings.SplitAfterN("s", "sep", 0)
	strings.SplitN("s", "sep", 0)
	strings.ToLower("s")
	strings.ToLowerSpecial(unicode.TurkishCase, "s")
	strings.ToTitle("s")
	strings.ToTitleSpecial(unicode.TurkishCase, "s")
	strings.ToUpper("s")
	strings.ToUpperSpecial(unicode.AzeriCase, "s")
	strings.ToValidUTF8("s", "replace")
	strings.Trim("s", "cutset")
	strings.TrimFunc("s", func(r rune) bool { return true })
	strings.TrimLeft("s", "cutset")
	strings.TrimLeftFunc("s", func(r rune) bool { return true })
	strings.TrimRight("s", "cutset")
	strings.TrimRightFunc("s", func(r rune) bool { return true })
	strings.TrimSpace("s")
	strings.TrimSuffix("s", "suffix")
	b := strings.Builder{}
	b.Cap()
	b.Grow(0)
	b.Len()
	b.Reset()
	b.String()
	b.Write(nil)
	b.WriteByte(0)
	b.WriteRune(0)
	b.WriteString("s")
	r := strings.NewReader("s")
	r.Len()
	r.Read(nil)
	r.ReadAt(nil, 0)
	r.ReadByte()
	r.ReadRune()
	r.Reset("s")
	r.Seek(0, 0)
	r.Size()
	r.UnreadByte()
	r.UnreadRune()
	r.WriteTo(os.Stdout)

	rp := strings.NewReplacer("a", "b")
	rp.Replace("s")

	fmt.Println("end of strings")
}

//go:noinline
func sortPackage() {
	sort.Find(0, func(i int) int { return i })
	sort.Float64s([]float64{})
	sort.Float64sAreSorted([]float64{})
	sort.Ints([]int{})
	sort.IntsAreSorted([]int{})
	sort.IsSorted(sort.StringSlice{"1", "2"})
	sort.Search(1, func(i int) bool { return true })
	sort.SearchFloat64s([]float64{}, 0)
	sort.SearchInts([]int{}, 0)
	sort.SearchStrings([]string{}, "x")
	sort.Slice([]string{"x"}, func(i, j int) bool { return true })
	sort.SliceIsSorted([]string{}, func(i, j int) bool { return true })
	sort.SliceStable([]string{}, func(i, j int) bool { return true })
	sort.Sort(sort.StringSlice{})
	sort.Stable(sort.StringSlice{})
	sort.Strings([]string{})
	sort.StringsAreSorted([]string{})
	f64s := sort.Float64Slice{1, 2}
	f64s.Len()
	f64s.Less(0, 0)
	f64s.Search(0)
	f64s.Sort()
	f64s.Swap(0, 1)
	sort.Reverse(f64s)

	fmt.Println("end of sort")

}

//go:noinline
func unicodeAllPackages() {
	unicodePackage()
	unicodeUtf16Package()
	unicodeUtf8Package()

	fmt.Println("end of all unicode packages")
}

//go:noinline
func unicodePackage() {
	var r rune = mathrand.Int31()
	unicode.In(r, unicode.Latin)
	unicode.Is(unicode.Latin, r)
	unicode.IsControl(r)
	unicode.IsDigit(r)
	unicode.IsGraphic(r)
	unicode.IsLetter(r)
	unicode.IsLower(r)
	unicode.IsMark(r)
	unicode.IsNumber(r)
	unicode.IsOneOf([]*unicode.RangeTable{unicode.Latin}, r)
	unicode.IsPrint(r)
	unicode.IsPunct(r)
	unicode.IsSpace(r)
	unicode.IsSymbol(r)
	unicode.IsTitle(r)
	unicode.IsUpper(r)
	unicode.SimpleFold(r)
	unicode.To(unicode.UpperCase, r)
	unicode.ToLower(r)
	unicode.ToTitle(r)
	unicode.ToUpper(r)

	fmt.Println("end of unicode")
}

//go:noinline
func unicodeUtf16Package() {
	var r rune = mathrand.Int31()
	var p []uint16
	p = utf16.AppendRune(p, r)
	var s = utf16.Decode(p)
	r = utf16.DecodeRune(r, r)
	p = utf16.Encode(s)
	r, _ = utf16.EncodeRune(r)
	utf16.IsSurrogate(r)

	fmt.Println("end of unicode/utf16")
}

//go:noinline
func unicodeUtf8Package() {
	var r rune = mathrand.Int31()
	var p []byte
	p = utf8.AppendRune(p, r)
	r, _ = utf8.DecodeLastRune(p)
	r, _ = utf8.DecodeLastRuneInString("string")
	r, _ = utf8.DecodeRune(p)
	r, _ = utf8.DecodeRuneInString("string")
	utf8.EncodeRune(p, r)
	utf8.FullRune(p)
	utf8.FullRuneInString("string")
	utf8.RuneCount(p)
	utf8.RuneCountInString("string")
	utf8.RuneLen(r)
	utf8.RuneStart(0)
	utf8.Valid(p)
	utf8.ValidRune(r)
	utf8.ValidString("string")

	fmt.Println("end of unicode/utf8")
}

/*
go:noinline
func unsafePackage() {
	var b byte = 0
	var aligned = unsafe.Alignof(b)
	fmt.Println(aligned)
	fmt.Println(unsafe.Sizeof(b))
	fmt.Println(unsafe.String(&b, 10))
	fmt.Println(unsafe.StringData("string"))
	s := unsafe.Slice(&b, 100)
	fmt.Println(unsafe.SliceData(s))
	fmt.Println(unsafe.Add(unsafe.Pointer(&b), 100))

	fmt.Println("end of unsafe package")
}
*/

func main() {
	archivePackage()
	bufioPackage()
	bytesPackage()
	compressPackage()
	containerPackage()
	contextPackage()
	cryptoPackage()
	databaseSqlPackage()
	debugPackage()
	errorsPackage()
	flagPackage()
	fmtPackage()
	ioAllPackage()
	logAllPackage()
	mathAllPackage()
	netAllPackage()
	osPackage()
	pathPackage()
	pathFilepathPackage()
	pluginPackage()
	runtimePackage()
	syncPackage()
	stringsPackage()
	strconvPackage()
	sortPackage()
	textPackage()
	timePackage()
	unicodeAllPackages()
	//unsafePackage()
}
