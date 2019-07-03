package ldap

import (
	"fmt"
	"errors"
	"regexp"
	"strings"
	"crypto/md5"

	"gopkg.in/asn1-ber.v1"
)

// SimpleBindRequest represents a username/password bind operation
type SimpleBindRequest struct {
	// Username is the name of the Directory object that the client wishes to bind as
	Username string
	// Password is the credentials to bind with
	Password string
	// Controls are optional controls to send with the bind request
	Controls []Control
	// AllowEmptyPassword sets whether the client allows binding with an empty password
	// (normally used for unauthenticated bind).
	AllowEmptyPassword bool
}

// SimpleBindResult contains the response from the server
type SimpleBindResult struct {
	Controls []Control
}

// NewSimpleBindRequest returns a bind request
func NewSimpleBindRequest(username string, password string, controls []Control) *SimpleBindRequest {
	return &SimpleBindRequest{
		Username:           username,
		Password:           password,
		Controls:           controls,
		AllowEmptyPassword: false,
	}
}

func (bindRequest *SimpleBindRequest) encode() *ber.Packet {
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, bindRequest.Username, "User Name"))
	request.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, bindRequest.Password, "Password"))

	if len(bindRequest.Controls) > 0 {
		request.AppendChild(encodeControls(bindRequest.Controls))
	}

	return request
}

// SimpleBind performs the simple bind operation defined in the given request
func (l *Conn) SimpleBind(simpleBindRequest *SimpleBindRequest) (*SimpleBindResult, error) {
	if simpleBindRequest.Password == "" && !simpleBindRequest.AllowEmptyPassword {
		return nil, NewError(ErrorEmptyPassword, errors.New("ldap: empty password not allowed by the client"))
	}

	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, l.nextMessageID(), "MessageID"))
	encodedBindRequest := simpleBindRequest.encode()
	packet.AppendChild(encodedBindRequest)

	if l.Debug {
		ber.PrintPacket(packet)
	}

	msgCtx, err := l.sendMessage(packet)
	if err != nil {
		return nil, err
	}
	defer l.finishMessage(msgCtx)

	packetResponse, ok := <-msgCtx.responses
	if !ok {
		return nil, NewError(ErrorNetwork, errors.New("ldap: response channel closed"))
	}
	packet, err = packetResponse.ReadPacket()
	l.Debug.Printf("%d: got response %p", msgCtx.id, packet)
	if err != nil {
		return nil, err
	}

	if l.Debug {
		if err := addLDAPDescriptions(packet); err != nil {
			return nil, err
		}
		ber.PrintPacket(packet)
	}

	result := &SimpleBindResult{
		Controls: make([]Control, 0),
	}

	if len(packet.Children) == 3 {
		for _, child := range packet.Children[2].Children {
			result.Controls = append(result.Controls, DecodeControl(child))
		}
	}

	resultCode, resultDescription := getLDAPResultCode(packet)
	if resultCode != 0 {
		return result, NewError(resultCode, errors.New(resultDescription))
	}

	return result, nil
}

// Bind performs a bind with the given username and password.
//
// It does not allow unauthenticated bind (i.e. empty password). Use the UnauthenticatedBind method
// for that.
func (l *Conn) Bind(username, password string) error {
	req := &SimpleBindRequest{
		Username:           username,
		Password:           password,
		AllowEmptyPassword: false,
	}
	_, err := l.SimpleBind(req)
	return err
}

// UnauthenticatedBind performs an unauthenticated bind.
//
// A username may be provided for trace (e.g. logging) purpose only, but it is normally not
// authenticated or otherwise validated by the LDAP server.
//
// See https://tools.ietf.org/html/rfc4513#section-5.1.2 .
// See https://tools.ietf.org/html/rfc4513#section-6.3.1 .
func (l *Conn) UnauthenticatedBind(username string) error {
	req := &SimpleBindRequest{
		Username:           username,
		Password:           "",
		AllowEmptyPassword: true,
	}
	_, err := l.SimpleBind(req)
	return err
}

// TODO: The documentation

type saslStartResult struct {
	DigestUri string

	Realm string

	Nonce string

	Ciphers []string

	Algorithm string

	Qops []string

	Charset string
}

type SaslMechanism string

const (
	MECH_DIGEST_MD5 SaslMechanism = "DIGEST-MD5"
)

func DecodeServerSaslCreds(packet *ber.Packet) map[string]string {
	res := make(map[string]string)

	re := regexp.MustCompile(`(\w+)=([\w-:/\+=]+|"[\w-:/\+=,(?=\w)]+")`)
	for _, match := range re.FindAllStringSubmatch(packet.Data.String(), -1) {
		res[match[1]] = strings.Trim(match[2], `"`)
	}

	return res
}

// Discuss the server for SASL to get confirmation and availability of the requested mechanism
func (l *Conn) startSaslBind(mechanism SaslMechanism) (*saslStartResult, error) {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")

	// Message ID
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, l.nextMessageID(), "MessageID"))

	// Request
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Name"))

	// Sasl
	sasl := ber.Encode(ber.ClassContext, ber.TypeConstructed, ApplicationSearchRequest, nil, "Sasl")
	sasl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(mechanism), "Mechanism"))

	request.AppendChild(sasl)
	packet.AppendChild(request)

	if l.Debug {
		ber.PrintPacket(packet)
	}

	msgCtx, err := l.sendMessage(packet)
	if err != nil {
		return nil, err
	}
	defer l.finishMessage(msgCtx)

	packetResponse, ok := <-msgCtx.responses
	if !ok {
		return nil, NewError(ErrorNetwork, errors.New("ldap: response channel closed"))
	}
	packet, err = packetResponse.ReadPacket()
	l.Debug.Printf("%d: got response %p", msgCtx.id, packet)
	if err != nil {
		return nil, err
	}

	if l.Debug {
		if err := addLDAPDescriptions(packet); err != nil {
			return nil, err
		}
		ber.PrintPacket(packet)
	}

	result := &saslStartResult{}

	if len(packet.Children) == 2 {
		if len(packet.Children[1].Children) == 4 {
			// Read nonce, realm, charset, qop, algorithm, cipher
			l.Debug.Printf("Server response: %s", packet.Children[1].Children[3].Data.String())
			headers := DecodeServerSaslCreds(packet.Children[1].Children[3])
			l.Debug.Printf("Headers: %v", headers)
			for k, v := range headers {
				switch strings.ToLower(k) {
				case "nonce":
					result.Nonce = v

				case "realm":
					result.Realm = v

				case "charset":
					result.Charset = v

				case "algorithm":
					result.Algorithm = v

				case "cipher":
					result.Ciphers = strings.Split(v, ",")

				case "qop":
					result.Qops = strings.Split(v, ",")
				}
			}
		}
	}

	l.Debug.Printf("Result: %#v", result)

	resultCode, resultDescription := getLDAPResultCode(packet)
	if resultCode != 0 {
		return result, NewError(resultCode, errors.New(resultDescription))
	}

	return result, nil
}

// TODO: The documentation

type DigestMd5BindRequest struct {
	Username string

	Password string

	Controls []Control

	DigestUri string

	params saslStartResult
}

type DigestMd5BindResult struct {
	Controls []Control
}

func NewDigestMd5BindRequest(username, password, digestUri string, controls []Control) *DigestMd5BindRequest {
	return &DigestMd5BindRequest{
		Username: username,
		Password: password,
		Controls: controls,
		DigestUri: digestUri,
	}
}

//https://tools.ietf.org/html/rfc2831
func (bindRequest *DigestMd5BindRequest) encode() *ber.Packet {
	authzid := ""
	cnonce := "37c4805fac7d9b3c56a7"
	nc := "00000001"
	qop := "auth"
	normDn := strings.ToUpper(bindRequest.Username)

	if 0 == len(bindRequest.params.DigestUri) {
		bindRequest.params.DigestUri = bindRequest.DigestUri
	}

	a := fmt.Sprintf("dn:%s:%s:%s", normDn, bindRequest.params.Realm, bindRequest.Password)
	h := md5.Sum([]byte(a))

	a1 := fmt.Sprintf("%s:%s:%s", h, bindRequest.params.Nonce, cnonce)
	if "" != authzid {
		a1 = fmt.Sprintf("%s:%s", a1, authzid)
	}
	h1 := md5.Sum([]byte(a1))

	a2 := fmt.Sprintf("AUTHENTICATE:%s", bindRequest.params.DigestUri)
	if "auth" != qop {
		a2 = fmt.Sprintf("%s:%s", a2, "00000000000000000000000000000000")
	}
	h2 := md5.Sum([]byte(a2))

	response := fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%x:%s:%s:%s:%s:%x", h1, bindRequest.params.Nonce, nc, cnonce, qop, h2))))

	credentials := fmt.Sprintf(
		`charset=utf-8,username="dn:%s",realm="%s",nonce="%s",nc=%s,cnonce="%s",response="%s",qop=%s,digest-uri="%s"`,
		normDn,
		bindRequest.params.Realm,
		bindRequest.params.Nonce,
		nc,
		cnonce,
		response,
		qop,
		bindRequest.params.DigestUri,
	)

	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, bindRequest.Username, "Name"))

	sasl := ber.Encode(ber.ClassContext, ber.TypeConstructed, ApplicationSearchRequest, nil, "Sasl")
	sasl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(MECH_DIGEST_MD5), "Mechanism"))
	sasl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, credentials, "Credentials"))
	request.AppendChild(sasl)

	if len(bindRequest.Controls) > 0 {
		request.AppendChild(encodeControls(bindRequest.Controls))
	}

	return request
}

//https://tools.ietf.org/html/draft-wahl-ldap-digest-example-00
func (l *Conn) DigestMd5Bind(digestMd5BindRequest *DigestMd5BindRequest) (*DigestMd5BindResult, error) {
	// TODO: Check input
	//if digestMd5BindRequest.Password == "" {
	//	return nil, NewError(ErrorEmptyPassword, errors.New("ldap: empty password not allowed by the client"))
	//}

	if v, err := l.startSaslBind(MECH_DIGEST_MD5); nil == err ||
		IsErrorWithCode(err, LDAPResultSaslBindInProgress) {
		digestMd5BindRequest.params = *v
	} else {
		return nil, err
	}

	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, l.nextMessageID(), "MessageID"))
	encodedBindRequest := digestMd5BindRequest.encode()
	packet.AppendChild(encodedBindRequest)

	if l.Debug {
		ber.PrintPacket(packet)
	}

	msgCtx, err := l.sendMessage(packet)
	if err != nil {
		return nil, err
	}
	defer l.finishMessage(msgCtx)

	packetResponse, ok := <-msgCtx.responses
	if !ok {
		return nil, NewError(ErrorNetwork, errors.New("ldap: response channel closed"))
	}
	packet, err = packetResponse.ReadPacket()
	l.Debug.Printf("%d: got response %p", msgCtx.id, packet)
	if err != nil {
		return nil, err
	}

	if l.Debug {
		if err := addLDAPDescriptions(packet); err != nil {
			return nil, err
		}
		ber.PrintPacket(packet)
	}

	result := &DigestMd5BindResult{
		Controls: make([]Control, 0),
	}

	if len(packet.Children) == 3 {
		for _, child := range packet.Children[2].Children {
			result.Controls = append(result.Controls, DecodeControl(child))
		}
	}

	resultCode, resultDescription := getLDAPResultCode(packet)
	if resultCode != 0 {
		return result, NewError(resultCode, errors.New(resultDescription))
	}

	return result, nil
}
