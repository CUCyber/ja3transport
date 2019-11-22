package ja3client

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	tls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// GreasePlaceholder is a random value (well, kindof '0x?a?a) specified in a
// random RFC.
const GreasePlaceholder = 0x0a0a

// extMap maps extension values to the TLSExtension object associated with the
// number. Some values are not put in here because they must be applied in a
// special way. For example, "10" is the SupportedCurves extension which is also
// used to calculate the JA3 signature. These JA3-dependent values are applied
// after the instantiation of the map.
var extMap = map[string]tls.TLSExtension{
	"0": &tls.SNIExtension{},
	"5": &tls.StatusRequestExtension{},
	// These are applied later
	// "10": &tls.SupportedCurvesExtension{...}
	// "11": &tls.SupportedPointsExtension{...}
	"13": &tls.SignatureAlgorithmsExtension{
		SupportedSignatureAlgorithms: []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
			tls.PSSWithSHA256,
			tls.PKCS1WithSHA256,
			tls.ECDSAWithP384AndSHA384,
			tls.PSSWithSHA384,
			tls.PKCS1WithSHA384,
			tls.PSSWithSHA512,
			tls.PKCS1WithSHA512,
			tls.PKCS1WithSHA1,
		},
	},
	"16": &tls.ALPNExtension{
		AlpnProtocols: []string{"h2", "http/1.1"},
	},
	"18": &tls.SCTExtension{},
	"21": &tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
	"23": &tls.UtlsExtendedMasterSecretExtension{},
	"27": &tls.FakeCertCompressionAlgsExtension{},
	"28": &tls.FakeRecordSizeLimitExtension{},
	"35": &tls.SessionTicketExtension{},
	"43": &tls.SupportedVersionsExtension{[]uint16{
		tls.GREASE_PLACEHOLDER,
		tls.VersionTLS13,
		tls.VersionTLS12,
		tls.VersionTLS11,
		tls.VersionTLS10}},
	"44": &tls.CookieExtension{},
	"45": &tls.PSKKeyExchangeModesExtension{[]uint8{
		tls.PskModeDHE,
	}},
	"51": &tls.KeyShareExtension{[]tls.KeyShare{
		{Group: tls.CurveID(GreasePlaceholder), Data: []byte{0}},
		{Group: tls.X25519},
	}},
	"13172": &tls.NPNExtension{},
	"65281": &tls.RenegotiationInfoExtension{
		Renegotiation: tls.RenegotiateOnceAsClient,
	},
}

// JA3Client contains is similar to http.Client
type JA3Client struct {
	Config  *tls.Config
	Timeout time.Duration
	Browser Browser
	Spec    *tls.ClientHelloSpec
}

func urlToHost(target *url.URL) *url.URL {
	if !strings.Contains(target.Host, ":") {
		if target.Scheme == "http" {
			target.Host = target.Host + ":80"
		} else if target.Schema == "https" {
			target.Host = target.Host + ":443"
		}
	}
	return target
}

func ErrExtensionNotExist(e string) error {
	return fmt.Errorf("Extension does not exist: %v\n", e)
}

// New creates a JA3Client based on a Browser struct
func New(b Browser) (*JA3Client, error) {
	client, err := NewWithString(b.JA3)
	if err != nil {
		return nil, err
	}
	client.Browser = b
	return client, nil
}

// NewWithString creates a JA3 client with the specified JA3 string
func NewWithString(ja3 string) (*JA3Client, error) {
	spec, err := stringToSpec(ja3)
	if err != nil {
		return nil, err
	}

	return &JA3Client{
		Spec:    spec,
		Timeout: time.Duration(15) * time.Second,
		Config:  &tls.Config{},
		Browser: Browser{JA3: ja3},
	}, nil
}

// stringToSpec creates a ClientHelloSpec based on a JA3 string
func stringToSpec(ja3 string) (*tls.ClientHelloSpec, error) {
	tokens := strings.Split(ja3, ",")

	version := tokens[0]
	ciphers := strings.Split(tokens[1], "-")
	extensions := strings.Split(tokens[2], "-")
	curves := strings.Split(tokens[3], "-")
	if len(curves) == 1 && curves[0] == "" {
		curves = []string{}
	}
	pointFormats := strings.Split(tokens[4], "-")
	if len(pointFormats) == 1 && pointFormats[0] == "" {
		pointFormats = []string{}
	}

	// parse curves
	var targetCurves []tls.CurveID
	for _, c := range curves {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return nil, err
		}
		targetCurves = append(targetCurves, tls.CurveID(cid))
	}
	extMap["10"] = &tls.SupportedCurvesExtension{targetCurves}

	// parse point formats
	var targetPointFormats []byte
	for _, p := range pointFormats {
		pid, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return nil, err
		}
		targetPointFormats = append(targetPointFormats, byte(pid))
	}
	extMap["11"] = &tls.SupportedPointsExtension{SupportedPoints: targetPointFormats}

	// build extenions list
	var exts []tls.TLSExtension
	for _, e := range extensions {
		te, ok := extMap[e]
		if !ok {
			return nil, ErrExtensionNotExist(e)
		}
		exts = append(exts, te)
	}

	// build SSLVersion
	vid64, err := strconv.ParseUint(version, 10, 16)
	if err != nil {
		return nil, err
	}
	vid := uint16(vid64)

	// build CipherSuites
	var suites []uint16
	for _, c := range ciphers {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return nil, err
		}
		suites = append(suites, uint16(cid))
	}

	return &tls.ClientHelloSpec{
		TLSVersMin:         vid,
		TLSVersMax:         vid,
		CipherSuites:       suites,
		CompressionMethods: []byte{0},
		Extensions:         exts,
		GetSessionID:       sha256.Sum256,
	}, nil
}

// Do sends an HTTP request and returns an HTTP response, following policy
// (such as redirects, cookies, auth) as configured on the client.
func (c *JA3Client) Do(req *http.Request) (*http.Response, error) {
	if _, ok := req.Header["User-Agent"]; !ok && c.Browser.UserAgent != "" {
		req.Header.Set("User-Agent", c.Browser.UserAgent)
	}

	if req.URL.Scheme == "http" {
		return http.DefaultClient.Do(req)
	}

	target = urlToHost(req.URL)
	hostname := strings.Split(target.Host, ":")[0]

	if c.Config.ServerName == "" {
		c.Config.ServerName = hostname
	}

	dialConn, err := net.DialTimeout("tcp", target.Host, c.Timeout)
	if err != nil {
		return nil, err
	}
	uTlsConn := tls.UClient(dialConn, c.Config, tls.HelloCustom)
	defer uTlsConn.Close()

	if err := uTlsConn.ApplyPreset(c.Spec); err != nil {
		return nil, err
	}

	if err := uTlsConn.Handshake(); err != nil {
		return nil, err
	}

	switch uTlsConn.HandshakeState.ServerHello.AlpnProtocol {
	case "h2":
		req.Proto = "HTTP/2.0"
		req.ProtoMajor = 2
		req.ProtoMinor = 0

		tr := http2.Transport{}
		cConn, err := tr.NewClientConn(uTlsConn)
		if err != nil {
			return nil, err
		}
		return cConn.RoundTrip(req)
	case "http/1.1", "":
		req.Proto = "HTTP/1.1"
		req.ProtoMajor = 1
		req.ProtoMinor = 1

		if err := req.Write(uTlsConn); err != nil {
			return nil, err
		}
		return http.ReadResponse(bufio.NewReader(uTlsConn), req)
	default:
		return nil, err
	}
}

// Get issues a GET to the specified URL.
func (c *JA3Client) Get(targetURL string) (*http.Response, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Post issues a POST to the specified URL.
func (c *JA3Client) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.Do(req)
}

// Head issues a HEAD to the specified URL.
func (c *JA3Client) Head(url string) (resp *http.Response, err error) {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// PostForm issues a POST to the specified URL,
// with data's keys and values URL-encoded as the request body.
func (c *JA3Client) PostForm(url string, data url.Values) (resp *http.Response, err error) {
	return c.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}
