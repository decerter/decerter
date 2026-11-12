// SPDX-License-Identifier: AGPL-3.0-only

//go:build unit

package tlsrecord_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/decerter/decerter/internal/tlsrecord"
)

// the records and secrets of the Simple 1-RTT Handshake of RFC 8448 section 3, TLS_AES_128_GCM_SHA256 with SNI "server"
const (
	// {client} send handshake record: ClientHello
	rfc8448ClientHello string = "16030100c4010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001"
	// {client} send handshake record of the Resumed 0-RTT Handshake (section 4): a ClientHello with early_data
	rfc8448EarlyClientHello string = "1603010200010001fc03031bc3ceb6bbe39cff938355b5a50adb6db21b7a6af649d7b4bc419d7876487d95000006130113031302010001cd0000000b0009000006736572766572ff01000100000a00140012001d00170018001901000101010201030104003300260024001d0020e4ffb68ac05f8d96c99da26698346c6be16482badddafe051a66b4f18d668f0b002a0000002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c0002400100150057000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002900dd00b800b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b0070ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3ff5dd36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda721470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e93343694093934ae4d357fad6aacb0021203add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d"
	// {server} send handshake record: ServerHello
	rfc8448ServerHello string = "160303005a020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304"
	// {server} send handshake record: EncryptedExtensions, Certificate, CertificateVerify, Finished
	rfc8448ServerHandshake string = "17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35edf7869fcf40aa40aa2b8ea73f848a7ca07612ef9f945cb960b4068905123ea78b111b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5ecf7b13bd9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9d7477609aee6e122a4cf51427325250c7d0e509289444c9b3a648f1d71035d2ed65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd610928d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead686945ba246ab66e5edd8044b4c6de3fcf2a89441ac66272fd8fb330ef8190579b3684596c960bd596eea520a56a8d650f563aad27409960dca63d3e688611ea5e22f4415cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26f59ecaba9acbbb317b66d902f4f292a36ac1b639c637ce343117b659622245317b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e1b7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da8c87c843f5e56eb4c5e8280a2b48052cf93b16499a66db7cca71e4599426f7d461e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe5a37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb992f2b992f67f8afe67f76913fa388cb5630c8ca01e0c65d11c66a1e2ac4c85977b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b66763038ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b845e275592c12335ee340bbc4fddd502784016e4b3be7ef04dda49f4b440a30cb5d2af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e750edc53370d2b"
	// its payload
	rfc8448ServerHandshakePlain string = "080000240022000a00140012001d00170018001901000101010201030104001c00024001000000000b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de100000f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718"
	// {client} send handshake record: Finished
	rfc8448ClientFinished string = "170303003575ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc44d87f38f80338ac98fc46deb384bd1caeacab6867d726c40546"
	// its payload
	rfc8448ClientFinishedPlain string = "14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61"
	// {server} send handshake record: NewSessionTicket
	rfc8448ServerTicket string = "17030300de3a6b8f90414a97d6959c3487680de5134a2b240e6cffac116e95d41d6af8f6b580dcf3d11d63c758db289a015940252f55713e061dc13e078891a38efbcf5753ad8ef170ad3c7353d16d9da773b9ca7f2b9fa1b6c0d4a3d03f75e09c30ba1e62972ac46f75f7b981be63439b2999ce13064615139891d5e4c5b406f16e3fc181a77ca475840025db2f0a77f81b5ab05b94c01346755f69232c86519d86cbeeac87aac347d143f9605d64f650db4d023e70e952ca49fe5137121c74bc2697687e248746d6df353005f3bce18696129c8153556b3b6c6779b37bf15985684f"
	// its payload
	rfc8448ServerTicketPlain string = "040000c90000001efad6aac502000000b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b0070ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3ff5dd36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda721470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e93343694093934ae4d3570008002a000400000400"
	// {client} send application_data record
	rfc8448ClientData string = "1703030043a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f2b9819a8a5b46b395bd54a9a20441e2b62974e1f5a6292a2977014bd1e3deae63aeebb21694915e4"
	// {server} send application_data record
	rfc8448ServerData string = "17030300432e937e11ef4ac740e538ad36005fc4a46932fc3225d05f82aa1b36e30efaf97d90e6dffc602dcb501a59a8fcc49c4bf2e5f0a21c0047c2abf332540dd032e167c2955d"
	// the payload of both application_data records
	rfc8448DataPlain string = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031"
	// {client} send alert record
	rfc8448ClientAlert string = "1703030013c9872760655666b74d7ff1153efd6db6d0b0e3"
	// {server} send alert record
	rfc8448ServerAlert string = "1703030013b58fd67166ebf599d24720cfbe7efa7a8864a9"
	// {server} derive secret "tls13 c hs traffic"
	rfc8448ClientHandshakeSecret string = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"
	// {server} derive secret "tls13 s hs traffic"
	rfc8448ServerHandshakeSecret string = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"
	// {server} derive secret "tls13 c ap traffic"
	rfc8448ClientTrafficSecret string = "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"
	// {server} derive secret "tls13 s ap traffic"
	rfc8448ServerTrafficSecret string = "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"
)

// one record of a recorded session: the bytes on the wire and what reading it has to give
// Plain is the decrypted payload, empty for a record that is not protected
type vectorRecord struct {
	Direction   tlsrecord.Direction
	Record      string
	ContentType tlsrecord.ContentType
	Sequence    uint64
	Plain       string
}

// one TLS 1.3 suite of the test's own record sealing
type suiteCase struct {
	ID        uint16
	NewHash   func() hash.Hash
	KeyLength int
	NewAEAD   func(key []byte) (aead cipher.AEAD, err error)
}

var (
	rfc8448Records = []vectorRecord{
		{Direction: tlsrecord.ClientDirection, Record: rfc8448ClientHello, ContentType: tlsrecord.HandshakeContentType, Sequence: 0, Plain: ""},
		{Direction: tlsrecord.ServerDirection, Record: rfc8448ServerHello, ContentType: tlsrecord.HandshakeContentType, Sequence: 0, Plain: ""},
		{Direction: tlsrecord.ServerDirection, Record: rfc8448ServerHandshake, ContentType: tlsrecord.HandshakeContentType, Sequence: 0, Plain: rfc8448ServerHandshakePlain},
		{Direction: tlsrecord.ClientDirection, Record: rfc8448ClientFinished, ContentType: tlsrecord.HandshakeContentType, Sequence: 0, Plain: rfc8448ClientFinishedPlain},
		{Direction: tlsrecord.ServerDirection, Record: rfc8448ServerTicket, ContentType: tlsrecord.HandshakeContentType, Sequence: 0, Plain: rfc8448ServerTicketPlain},
		{Direction: tlsrecord.ClientDirection, Record: rfc8448ClientData, ContentType: tlsrecord.ApplicationDataContentType, Sequence: 0, Plain: rfc8448DataPlain},
		{Direction: tlsrecord.ServerDirection, Record: rfc8448ServerData, ContentType: tlsrecord.ApplicationDataContentType, Sequence: 1, Plain: rfc8448DataPlain},
		{Direction: tlsrecord.ClientDirection, Record: rfc8448ClientAlert, ContentType: tlsrecord.AlertContentType, Sequence: 1, Plain: "0100"},
		{Direction: tlsrecord.ServerDirection, Record: rfc8448ServerAlert, ContentType: tlsrecord.AlertContentType, Sequence: 2, Plain: "0100"},
	}
	suiteCases = []suiteCase{
		{ID: 0x1301, NewHash: sha256.New, KeyLength: 16, NewAEAD: newGCM},
		{ID: 0x1302, NewHash: sha512.New384, KeyLength: 32, NewAEAD: newGCM},
		{ID: 0x1303, NewHash: sha256.New, KeyLength: chacha20poly1305.KeySize, NewAEAD: chacha20poly1305.New},
	}
)

// Test if tlsrecord.Feed returns with the expected output for the records of RFC 8448.
func TestRFC8448Positive(state *testing.T) {
	secrets, err := rfc8448Secrets()

	if err != nil {
		state.Fatalf("Test of tlsrecord.Feed failed, cannot decode secrets, error: %s", err.Error())
	}

	// whole records and every byte on its own, with the secrets there at the start and set after the last record
	for _, isSplit := range []bool{false, true} {
		for _, isHeld := range []bool{false, true} {
			err = testRFC8448Feed(rfc8448Records, secrets, isSplit, isHeld)

			if err != nil {
				state.Errorf("Test of tlsrecord.Feed failed, split %v, held %v, error: %s", isSplit, isHeld, err.Error())
				return
			}
		}
	}
}

// Test if tlsrecord.Feed returns with the expected errors for changed records and secrets of RFC 8448.
func TestRFC8448Negative(state *testing.T) {
	secrets, err := rfc8448Secrets()

	if err != nil {
		state.Fatalf("Test of tlsrecord.Feed failed, cannot decode secrets, error: %s", err.Error())
	}

	wrongHandshake := secrets
	wrongHandshake.ServerHandshakeTrafficSecret = bytes.Clone(secrets.ServerHandshakeTrafficSecret)
	wrongHandshake.ServerHandshakeTrafficSecret[0] ^= 1
	shortTraffic := secrets
	shortTraffic.ClientTrafficSecret = secrets.ClientTrafficSecret[:31]
	otherVersion := secrets
	otherVersion.Version = tlsrecord.VersionTLS12
	// the last byte of the tag, a ServerHello offering TLS_AES_128_CCM_SHA256, a record longer than any TLS allows
	tamperedData := rfc8448ServerData[:len(rfc8448ServerData)-2] + "00"
	ccmServerHello := rfc8448ServerHello[:88] + "1304" + rfc8448ServerHello[92:]
	overflowData := "17030348" + rfc8448ServerData[8:]
	negativeCases := []struct {
		Records []vectorRecord
		Secrets tlsrecord.Secrets
		Err     error
	}{
		{Records: rfc8448Records, Secrets: wrongHandshake, Err: tlsrecord.ErrBadRecordMAC},
		{Records: rfc8448Records, Secrets: shortTraffic, Err: tlsrecord.ErrSecrets},
		{Records: rfc8448Records, Secrets: otherVersion, Err: tlsrecord.ErrSecrets},
		{Records: replaceRecord(rfc8448Records, 6, tamperedData), Secrets: secrets, Err: tlsrecord.ErrBadRecordMAC},
		{Records: replaceRecord(rfc8448Records, 1, ccmServerHello), Secrets: secrets, Err: tlsrecord.ErrUnsupportedCipherSuite},
		{Records: replaceRecord(rfc8448Records, 6, overflowData), Secrets: secrets, Err: tlsrecord.ErrRecordOverflow},
		// a ServerHello without a ClientHello before it
		{Records: rfc8448Records[1:], Secrets: secrets, Err: tlsrecord.ErrUnexpectedRecord},
		{Records: replaceRecord(rfc8448Records, 0, rfc8448EarlyClientHello), Secrets: secrets, Err: tlsrecord.ErrEarlyData},
	}

	for index, negative := range negativeCases {
		for _, isHeld := range []bool{false, true} {
			err = testRFC8448Feed(negative.Records, negative.Secrets, false, isHeld)

			if !errors.Is(err, negative.Err) {
				state.Errorf("Test of tlsrecord.Feed function failed, case %d, held %v, error should be %v, error: %v", index, isHeld, negative.Err, err)
				return
			}
		}
	}
}

// Test if tlsrecord.Feed returns with the expected output for each TLS 1.3 suite, the records sealed by the test's own code.
func TestTLS13SuitesPositive(state *testing.T) {
	// the test's own key schedule and sealing first have to give the keys and records of RFC 8448
	err := testRFC8448Sealing()

	if err != nil {
		state.Fatalf("Test of tlsrecord.Feed failed, the test sealing does not match RFC 8448, error: %s", err.Error())
	}

	for _, positive := range suiteCases {
		err = testSuiteSession(positive, positive.NewHash().Size())

		if err != nil {
			state.Errorf("Test of tlsrecord.Feed failed, suite 0x%04x, error: %s", positive.ID, err.Error())
			return
		}
	}
}

// Test if tlsrecord.Feed returns with the expected errors for TLS 1.3 secrets that are not as long as the hash of the suite.
func TestTLS13SuitesNegative(state *testing.T) {
	for _, negative := range suiteCases {
		// a SHA-256 secret for a SHA-384 suite and the other way round
		secretLength := 32 + 48 - negative.NewHash().Size()
		err := testSuiteSession(negative, secretLength)

		if !errors.Is(err, tlsrecord.ErrSecrets) {
			state.Errorf("Test of tlsrecord.Feed function failed, suite 0x%04x, error should be %v, error: %v", negative.ID, tlsrecord.ErrSecrets, err)
			return
		}
	}
}

// Test if tlsrecord.CipherSuiteName and tlsrecord.VersionName return with the expected output.
func TestNamesPositive(state *testing.T) {
	suiteCases := []struct {
		ID   uint16
		Name string
	}{
		{ID: 0x1301, Name: "TLS_AES_128_GCM_SHA256"},
		{ID: 0x1303, Name: "TLS_CHACHA20_POLY1305_SHA256"},
		{ID: 0xc02b, Name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
		{ID: 0x000a, Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
		// a suite the package can't decrypt keeps its number
		{ID: 0x0005, Name: "0x0005"},
		{ID: 0x1304, Name: "0x1304"},
	}

	for _, positive := range suiteCases {
		if name := tlsrecord.CipherSuiteName(positive.ID); name != positive.Name {
			state.Errorf("Test of tlsrecord.CipherSuiteName function failed, name should be %s, name: %s", positive.Name, name)
			return
		}
	}

	versionCases := []struct {
		Version uint16
		Name    string
	}{
		{Version: tlsrecord.VersionTLS12, Name: "TLS1.2"},
		{Version: tlsrecord.VersionTLS13, Name: "TLS1.3"},
		{Version: tlsrecord.VersionDTLS12, Name: "DTLS1.2"},
		{Version: 0x0301, Name: "0x0301"},
	}

	for _, positive := range versionCases {
		if name := tlsrecord.VersionName(positive.Version); name != positive.Name {
			state.Errorf("Test of tlsrecord.VersionName function failed, name should be %s, name: %s", positive.Name, name)
			return
		}
	}
}

func testRFC8448Feed(vectors []vectorRecord, secrets tlsrecord.Secrets, isSplit bool, isHeld bool) (err error) {
	conn := tlsrecord.New(1<<20, false)
	records := []tlsrecord.Record{}

	if !isHeld {
		_, err = conn.SetSecrets(secrets)

		if err != nil {
			return
		}
	}

	for _, vector := range vectors {
		wire, decodeErr := hex.DecodeString(vector.Record)

		if err = decodeErr; err != nil {
			return
		}

		chunks := [][]byte{wire}

		if isSplit {
			chunks = nil

			for index := range wire {
				chunks = append(chunks, wire[index:index+1])
			}
		}

		for _, chunk := range chunks {
			fed, feedErr := conn.Feed(vector.Direction, chunk)

			if err = feedErr; err != nil {
				return
			}

			records = append(records, fed...)
		}
	}

	if isHeld {
		if !conn.Waiting() {
			err = errors.New("conn.Waiting return value was not true instead: false")
			return
		}

		released, secretsErr := conn.SetSecrets(secrets)

		if err = secretsErr; err != nil {
			return
		}

		records = append(records, released...)
	}

	if len(records) != len(vectors) {
		err = fmt.Errorf("record count was not %d instead: %d", len(vectors), len(records))
		return
	}

	for index, vector := range vectors {
		record := records[index]
		plain, decodeErr := hex.DecodeString(vector.Plain)

		if err = decodeErr; err != nil {
			return
		}

		isProtected := vector.Plain != ""

		if (record.Direction != vector.Direction) || (record.ContentType != vector.ContentType) || (record.Decrypted != isProtected) || (record.Length != len(vector.Record)/2) {
			err = fmt.Errorf("record %d return value was not direction %d type %d decrypted %v length %d instead: %d %d %v %d", index, vector.Direction, vector.ContentType, isProtected, len(vector.Record)/2, record.Direction, record.ContentType, record.Decrypted, record.Length)
			return
		}

		if isProtected && ((record.Sequence != vector.Sequence) || !bytes.Equal(record.Payload, plain)) {
			err = fmt.Errorf("record %d return value was not sequence %d payload %x instead: %d %x", index, vector.Sequence, plain, record.Sequence, record.Payload)
			return
		}
	}

	clientHello, err := hex.DecodeString(rfc8448ClientHello)

	if err != nil {
		return
	}

	session := conn.Session()

	// record header, handshake header and legacy_version come before the random
	if (session.Version != tlsrecord.VersionTLS13) || (session.CipherSuite != 0x1301) || (session.ServerName != "server") || (session.Protocol != "") || !bytes.Equal(session.ClientRandom[:], clientHello[11:43]) {
		err = fmt.Errorf("session return value was not as expected: %+v", session)
		return
	}

	return
}

// the keys and ivs of the four traffic secrets, and the client's application data and alert records byte for byte
func testRFC8448Sealing() (err error) {
	secrets, err := rfc8448Secrets()

	if err != nil {
		return
	}

	keyCases := []struct {
		Secret []byte
		Key    string
		IV     string
	}{
		{Secret: secrets.ServerHandshakeTrafficSecret, Key: "3fce516009c21727d0f2e4e86ee403bc", IV: "5d313eb2671276ee13000b30"},
		{Secret: secrets.ClientHandshakeTrafficSecret, Key: "dbfaa693d1762c5b666af5d950258d01", IV: "5bd3c71b836e0b76bb73265f"},
		{Secret: secrets.ServerTrafficSecret, Key: "9f02283b6c9c07efc26bb9f2ac92e356", IV: "cf782b88dd83549aadf1e984"},
		{Secret: secrets.ClientTrafficSecret, Key: "17422dda596ed5d9acd890e3c63f5051", IV: "5b78923dee08579033e523d9"},
	}

	for _, keyCase := range keyCases {
		key, iv, keyErr := trafficKey(suiteCases[0], keyCase.Secret)

		if err = keyErr; err != nil {
			return
		}

		if (hex.EncodeToString(key) != keyCase.Key) || (hex.EncodeToString(iv) != keyCase.IV) {
			err = fmt.Errorf("trafficKey return value was not %s %s instead: %x %x", keyCase.Key, keyCase.IV, key, iv)
			return
		}
	}

	plain, err := hex.DecodeString(rfc8448DataPlain)

	if err != nil {
		return
	}

	sealCases := []struct {
		ContentType tlsrecord.ContentType
		Sequence    uint64
		Plain       []byte
		Record      string
	}{
		{ContentType: tlsrecord.ApplicationDataContentType, Sequence: 0, Plain: plain, Record: rfc8448ClientData},
		{ContentType: tlsrecord.AlertContentType, Sequence: 1, Plain: []byte{1, 0}, Record: rfc8448ClientAlert},
	}

	for _, sealCase := range sealCases {
		record, sealErr := seal(suiteCases[0], secrets.ClientTrafficSecret, sealCase.Sequence, sealCase.ContentType, sealCase.Plain)

		if err = sealErr; err != nil {
			return
		}

		if hex.EncodeToString(record) != sealCase.Record {
			err = fmt.Errorf("seal return value was not %s instead: %x", sealCase.Record, record)
			return
		}
	}

	return
}

// a session of the suite with random secrets: the hellos of RFC 8448 with the suite put into the ServerHello, EncryptedExtensions with ALPN h2,
// application data both ways, a KeyUpdate of the client and application data under its next secret
func testSuiteSession(positive suiteCase, secretLength int) (err error) {
	secrets := tlsrecord.Secrets{Version: tlsrecord.VersionTLS13}
	trafficSecrets := []*[]byte{&secrets.ClientHandshakeTrafficSecret, &secrets.ServerHandshakeTrafficSecret, &secrets.ClientTrafficSecret, &secrets.ServerTrafficSecret}

	for _, trafficSecret := range trafficSecrets {
		*trafficSecret = make([]byte, secretLength)
		_, err = rand.Read(*trafficSecret)

		if err != nil {
			return
		}
	}

	clientHello, err := hex.DecodeString(rfc8448ClientHello)

	if err != nil {
		return
	}

	serverHello, err := hex.DecodeString(rfc8448ServerHello)

	if err != nil {
		return
	}

	binary.BigEndian.PutUint16(serverHello[44:46], positive.ID)
	// extensions length, application_layer_protocol_negotiation, protocol name list
	encryptedExtensions := handshake(8, []byte{0, 9, 0, 16, 0, 5, 0, 3, 2, 'h', '2'})
	finished := handshake(20, make([]byte, positive.NewHash().Size()))
	keyUpdate := handshake(24, []byte{0})
	nextClientSecret, err := expandLabel(positive.NewHash, secrets.ClientTrafficSecret, "traffic upd", nil, positive.NewHash().Size())

	if err != nil {
		return
	}

	steps := []struct {
		Direction   tlsrecord.Direction
		Secret      []byte
		Sequence    uint64
		ContentType tlsrecord.ContentType
		Plain       []byte
	}{
		{Direction: tlsrecord.ServerDirection, Secret: secrets.ServerHandshakeTrafficSecret, Sequence: 0, ContentType: tlsrecord.HandshakeContentType, Plain: append(encryptedExtensions, finished...)},
		{Direction: tlsrecord.ClientDirection, Secret: secrets.ClientHandshakeTrafficSecret, Sequence: 0, ContentType: tlsrecord.HandshakeContentType, Plain: finished},
		{Direction: tlsrecord.ClientDirection, Secret: secrets.ClientTrafficSecret, Sequence: 0, ContentType: tlsrecord.ApplicationDataContentType, Plain: []byte("GET / HTTP/1.1\r\n\r\n")},
		{Direction: tlsrecord.ServerDirection, Secret: secrets.ServerTrafficSecret, Sequence: 0, ContentType: tlsrecord.ApplicationDataContentType, Plain: []byte("HTTP/1.1 200 OK\r\n\r\n")},
		{Direction: tlsrecord.ClientDirection, Secret: secrets.ClientTrafficSecret, Sequence: 1, ContentType: tlsrecord.HandshakeContentType, Plain: keyUpdate},
		{Direction: tlsrecord.ClientDirection, Secret: nextClientSecret, Sequence: 0, ContentType: tlsrecord.ApplicationDataContentType, Plain: []byte("after the key update")},
	}
	conn := tlsrecord.New(1<<20, false)
	_, err = conn.SetSecrets(secrets)

	if err != nil {
		return
	}

	_, err = conn.Feed(tlsrecord.ClientDirection, clientHello)

	if err != nil {
		return
	}

	_, err = conn.Feed(tlsrecord.ServerDirection, serverHello)

	if err != nil {
		return
	}

	for index, step := range steps {
		record, sealErr := seal(positive, step.Secret, step.Sequence, step.ContentType, step.Plain)

		if err = sealErr; err != nil {
			return
		}

		records, feedErr := conn.Feed(step.Direction, record)

		if err = feedErr; err != nil {
			return
		}

		if (len(records) != 1) || !records[0].Decrypted || (records[0].ContentType != step.ContentType) || (records[0].Sequence != step.Sequence) || !bytes.Equal(records[0].Payload, step.Plain) {
			err = fmt.Errorf("records of step %d return value was not one decrypted record of type %d sequence %d instead: %+v", index, step.ContentType, step.Sequence, records)
			return
		}
	}

	session := conn.Session()

	if (session.CipherSuite != positive.ID) || (session.Protocol != "h2") {
		err = fmt.Errorf("session return value was not suite 0x%04x protocol h2 instead: 0x%04x %s", positive.ID, session.CipherSuite, session.Protocol)
		return
	}

	return
}

func rfc8448Secrets() (secrets tlsrecord.Secrets, err error) {
	secrets.Version = tlsrecord.VersionTLS13
	targets := map[string]*[]byte{
		rfc8448ClientHandshakeSecret: &secrets.ClientHandshakeTrafficSecret,
		rfc8448ServerHandshakeSecret: &secrets.ServerHandshakeTrafficSecret,
		rfc8448ClientTrafficSecret:   &secrets.ClientTrafficSecret,
		rfc8448ServerTrafficSecret:   &secrets.ServerTrafficSecret,
	}

	for text, target := range targets {
		*target, err = hex.DecodeString(text)

		if err != nil {
			return
		}
	}

	return
}

func replaceRecord(vectors []vectorRecord, index int, record string) (replaced []vectorRecord) {
	replaced = append([]vectorRecord{}, vectors...)
	replaced[index].Record = record
	return
}

func handshake(messageType uint8, body []byte) (message []byte) {
	message = append([]byte{messageType, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return
}

func newGCM(key []byte) (aead cipher.AEAD, err error) {
	block, blockErr := aes.NewCipher(key)

	if err = blockErr; err != nil {
		return
	}

	aead, err = cipher.NewGCM(block)
	return
}

// HKDF-Expand-Label (RFC 8446 section 7.1)
func expandLabel(newHash func() hash.Hash, secret []byte, label string, context []byte, length int) (out []byte, err error) {
	info := binary.BigEndian.AppendUint16(nil, uint16(length))
	info = append(info, byte(len("tls13 "+label)))
	info = append(info, "tls13 "+label...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	out, err = hkdf.Expand(newHash, secret, string(info), length)
	return
}

func trafficKey(suite suiteCase, trafficSecret []byte) (key []byte, iv []byte, err error) {
	key, err = expandLabel(suite.NewHash, trafficSecret, "key", nil, suite.KeyLength)

	if err != nil {
		return
	}

	iv, err = expandLabel(suite.NewHash, trafficSecret, "iv", nil, 12)
	return
}

// one TLS 1.3 record without padding (RFC 8446 section 5.2): the nonce is the iv with the sequence number xored into its end
func seal(suite suiteCase, trafficSecret []byte, sequence uint64, contentType tlsrecord.ContentType, plaintext []byte) (record []byte, err error) {
	key, nonce, err := trafficKey(suite, trafficSecret)

	if err != nil {
		return
	}

	aead, err := suite.NewAEAD(key)

	if err != nil {
		return
	}

	for index := range 8 {
		nonce[len(nonce)-1-index] ^= byte(sequence >> (8 * index))
	}

	inner := append(bytes.Clone(plaintext), byte(contentType))
	record = []byte{byte(tlsrecord.ApplicationDataContentType), 3, 3, 0, 0}
	binary.BigEndian.PutUint16(record[3:5], uint16(len(inner)+aead.Overhead()))
	record = aead.Seal(record, nonce, inner, record)
	return
}
