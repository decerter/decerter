// SPDX-License-Identifier: AGPL-3.0-only

package decode

import (
	"fmt"

	v1 "github.com/decerter/decerter/api"
)

// LDAP from RFC 4511 on the BER walker: the LDAPMessage with its message ID, the operation by its application tag, the result code of a response, and
// the DN or name a summary shows; the StartTLS extended operation (RFC 4511 4.14) switches the rest of the stream to TLS; CLDAP (RFC 1798) is the
// same messages over UDP; Kerberos from RFC 4120: the message types by their application tag, the realm and principal names, the error codes
const (
	ldapProtocol     string = "ldap"
	ldapTitle        string = "Lightweight Directory Access Protocol"
	kerberosProtocol string = "kerberos"
	kerberosTitle    string = "Kerberos"
	// the requestName of StartTLS
	ldapStartTLS string = "1.3.6.1.4.1.1466.20037"
	// the length prefix of Kerberos over TCP (RFC 4120 7.2.2)
	kerberosLengthBytes int = 4
)

var (
	ldapOperations = map[int]string{
		0: "bindRequest", 1: "bindResponse", 2: "unbindRequest", 3: "searchRequest", 4: "searchResEntry", 5: "searchResDone", 6: "modifyRequest",
		7: "modifyResponse", 8: "addRequest", 9: "addResponse", 10: "delRequest", 11: "delResponse", 12: "modDNRequest", 13: "modDNResponse",
		14: "compareRequest", 15: "compareResponse", 16: "abandonRequest", 19: "searchResRef", 23: "extendedReq", 24: "extendedResp",
		25: "intermediateResponse",
	}
	// the operations that are an LDAPResult (their first element is the result code)
	ldapResults = map[int]bool{1: true, 5: true, 7: true, 9: true, 11: true, 13: true, 15: true, 24: true}
	ldapCodes   = nameTable{names: map[uint16]string{
		0: "success", 1: "operationsError", 2: "protocolError", 3: "timeLimitExceeded", 4: "sizeLimitExceeded", 5: "compareFalse", 6: "compareTrue",
		7: "authMethodNotSupported", 8: "strongerAuthRequired", 10: "referral", 11: "adminLimitExceeded", 12: "unavailableCriticalExtension",
		13: "confidentialityRequired", 14: "saslBindInProgress", 16: "noSuchAttribute", 17: "undefinedAttributeType", 18: "inappropriateMatching",
		19: "constraintViolation", 20: "attributeOrValueExists", 21: "invalidAttributeSyntax", 32: "noSuchObject", 33: "aliasProblem",
		34: "invalidDNSyntax", 36: "aliasDereferencingProblem", 48: "inappropriateAuthentication", 49: "invalidCredentials",
		50: "insufficientAccessRights", 51: "busy", 52: "unavailable", 53: "unwillingToPerform", 54: "loopDetect", 64: "namingViolation",
		65: "objectClassViolation", 66: "notAllowedOnNonLeaf", 67: "notAllowedOnRDN", 68: "entryAlreadyExists", 69: "objectClassModsProhibited",
		71: "affectsMultipleDSAs", 80: "other",
	}, unknown: "resultCode %d"}
	ldapScopes      = map[int64]string{0: "baseObject", 1: "singleLevel", 2: "wholeSubtree"}
	kerberosMessage = map[int]string{
		10: "AS-REQ", 11: "AS-REP", 12: "TGS-REQ", 13: "TGS-REP", 14: "AP-REQ", 15: "AP-REP", 20: "KRB-SAFE", 21: "KRB-PRIV", 22: "KRB-CRED", 30: "KRB-ERROR",
	}
	kerberosErrors = nameTable{names: map[uint16]string{
		0: "KDC_ERR_NONE", 1: "KDC_ERR_NAME_EXP", 2: "KDC_ERR_SERVICE_EXP", 3: "KDC_ERR_BAD_PVNO", 6: "KDC_ERR_C_PRINCIPAL_UNKNOWN",
		7: "KDC_ERR_S_PRINCIPAL_UNKNOWN", 8: "KDC_ERR_PRINCIPAL_NOT_UNIQUE", 12: "KDC_ERR_POLICY", 13: "KDC_ERR_BADOPTION", 14: "KDC_ERR_ETYPE_NOSUPP",
		15: "KDC_ERR_SUMTYPE_NOSUPP", 16: "KDC_ERR_PADATA_TYPE_NOSUPP", 18: "KDC_ERR_CLIENT_REVOKED", 23: "KDC_ERR_KEY_EXPIRED",
		24: "KDC_ERR_PREAUTH_FAILED", 25: "KDC_ERR_PREAUTH_REQUIRED", 31: "KRB_AP_ERR_BAD_INTEGRITY", 32: "KRB_AP_ERR_TKT_EXPIRED",
		33: "KRB_AP_ERR_TKT_NYV", 34: "KRB_AP_ERR_REPEAT", 37: "KRB_AP_ERR_SKEW", 41: "KRB_AP_ERR_MODIFIED", 52: "KRB_ERR_RESPONSE_TOO_BIG",
		60: "KRB_ERR_GENERIC", 68: "KDC_ERR_WRONG_REALM",
	}, unknown: "error %d"}
	// the fields of the Kerberos messages by their context tag: KDC-REQ, its KDC-REQ-BODY, KDC-REP and KRB-ERROR
	kerberosRequest  = map[int]string{1: "pvno", 2: "msg-type", 3: "padata", 4: "req-body"}
	kerberosBody     = map[int]string{0: "kdc-options", 1: "cname", 2: "realm", 3: "sname", 4: "from", 5: "till", 6: "rtime", 7: "nonce", 8: "etype", 9: "addresses", 10: "enc-authorization-data", 11: "additional-tickets"}
	kerberosReply    = map[int]string{0: "pvno", 1: "msg-type", 2: "padata", 3: "crealm", 4: "cname", 5: "ticket", 6: "enc-part"}
	kerberosErrorTag = map[int]string{0: "pvno", 1: "msg-type", 2: "ctime", 3: "cusec", 4: "stime", 5: "susec", 6: "error-code", 7: "crealm", 8: "cname", 9: "realm", 10: "sname", 11: "e-text", 12: "e-data"}
	kerberosAP       = map[int]string{0: "pvno", 1: "msg-type", 2: "ap-options", 3: "ticket", 4: "authenticator", 5: "enc-part"}
)

func init() {
	register(decoder{
		Protocol:   ldapProtocol,
		Title:      ldapTitle,
		Ports:      []Port{{Layer: v1.TCPLayer, Number: 389}, {Layer: v1.UDPLayer, Number: 389}, {Layer: v1.TLSLayer, Number: 636}, {Layer: v1.TCPLayer, Number: 3268}, {Layer: v1.TLSLayer, Number: 3269}},
		hint:       noHint,
		sniff:      ldapSniff,
		decode:     framedDecode(ldapProtocol),
		fromTarget: nil,
		frame:      ldapFrame,
		pdu:        ldapPDU,
		unit:       "message",
	})
	register(decoder{
		Protocol:   kerberosProtocol,
		Title:      kerberosTitle,
		Ports:      []Port{{Layer: v1.TCPLayer, Number: 88}, {Layer: v1.UDPLayer, Number: 88}},
		hint:       noHint,
		sniff:      kerberosSniff,
		decode:     framedDecode(kerberosProtocol),
		fromTarget: nil,
		frame:      kerberosFrame,
		pdu:        kerberosPDU,
		unit:       "message",
	})
}

// a SEQUENCE of an INTEGER and an application tag of a known operation, the whole message there, is certain
func ldapSniff(data []byte, context Context) (score int) {
	if (len(data) < 7) || (data[0] != 0x30) {
		return
	}

	reader := &berReader{data: data, elements: 0}
	message := reader.read(0, len(data), 0)

	if (len(message.children) < 2) || (message.children[0].class != universalClass) || (message.children[0].tag != 2) || (message.children[1].class != applicationClass) {
		return
	}

	if _, isKnown := ldapOperations[message.children[1].tag]; isKnown && !message.hasError() {
		score = 90
	}

	return
}

// one LDAPMessage; LDAP has no indefinite lengths
func ldapFrame(data []byte, state *streamState) (length int) {
	if (len(data) >= 2) && (data[1] == 0x80) {
		length = -1
		return
	}

	length = berFrame(data, state)
	return
}

func ldapPDU(tree *Tree, data []byte, start int, state *streamState) (root *node) {
	reader := &berReader{data: data, elements: 0}
	message := reader.read(start, len(data), 0)
	operation := message.first()

	if (operation != nil) && (len(message.children) > 1) {
		operation = message.children[1]
	}

	identifier, _ := message.first().integer(data)
	operationName := ""

	if (operation != nil) && (operation.class == applicationClass) {
		operationName = ldapOperations[operation.tag]
	}

	if operationName == "" {
		operationName = "unknown operation"
	}

	label := func(element *berElement, parent *berElement) (name string, text string) {
		switch {
		case element == message:
			name, text = "ldap.LDAPMessage", "LDAPMessage"
		case (parent == message) && (element == message.first()):
			name, text = "ldap.messageID", "messageID"
		case element == operation:
			name, text = "ldap.protocolOp", operationName
		case (parent == message) && (element.class == contextClass) && (element.tag == 0):
			name, text = "ldap.controls", "controls"
		case (parent == operation) && (element == operation.first()) && ldapResults[operation.tag]:
			name, text = "ldap.resultCode", "resultCode"
		}

		return
	}

	root = berNodes(tree, nil, data, message, label, nil)
	tree.setName(root, ldapProtocol)
	tree.setLabel(root, ldapTitle+" ("+operationName+")")
	summary := fmt.Sprintf("LDAP %s(%d)", operationName, identifier)

	if operation != nil {
		summary += ldapDetail(data, operation, state)
	}

	tree.addSummary(summary)
	return
}

// the tail of the summary of an operation: the DN of a request, the result code of a response, the name of an extended operation
func ldapDetail(data []byte, operation *berElement, state *streamState) (detail string) {
	children := operation.children

	switch {
	case ldapResults[operation.tag] && (len(children) >= 2):
		code, _ := children[0].integer(data)
		detail = " " + shortName(ldapCodes, uint16(code))

		if matched := children[1].contents(data); len(matched) > 0 {
			detail += " " + textValue(matched)
		}

		if (len(children) >= 3) && (len(children[2].contents(data)) > 0) {
			detail += " " + shortText(children[2].contents(data), 80)
		}

		// the server's answer to StartTLS: TLS comes after it
		if operation.tag == 24 {
			state.mode = starttlsMode
		}
	case (operation.tag == 0) && (len(children) >= 2):
		version, _ := children[0].integer(data)
		detail = fmt.Sprintf(" v%d %s", version, textValue(children[1].contents(data)))

		if (len(children) >= 3) && (children[2].class == contextClass) {
			detail += map[int]string{0: " simple", 3: " sasl"}[children[2].tag]
		}
	case (operation.tag == 3) && (len(children) >= 2):
		scope, _ := children[1].integer(data)
		detail = fmt.Sprintf(" %s %s", textValue(children[0].contents(data)), ldapScopes[scope])
	case (operation.tag == 6) || (operation.tag == 8) || (operation.tag == 12) || (operation.tag == 14):
		if len(children) > 0 {
			detail = " " + textValue(children[0].contents(data))
		}
	case (operation.tag == 10) || (operation.tag == 16):
		detail = " " + operation.valueText(data)
	case operation.tag == 23:
		if name := operation.context(0); name != nil {
			detail = " " + string(name.contents(data))

			if string(name.contents(data)) == ldapStartTLS {
				detail += " (StartTLS)"
				state.mode = starttlsMode
			}
		}
	case operation.tag == 4:
		if len(children) > 0 {
			detail = " " + textValue(children[0].contents(data))
		}
	}

	return
}

// a known message type with the protocol version 5 inside is certain
func kerberosSniff(data []byte, context Context) (score int) {
	if context.Transport == StreamTransport {
		if len(data) < kerberosLengthBytes+2 {
			return
		}

		data = data[kerberosLengthBytes:]
	}

	if (len(data) < 2) || (data[0]&0xe0 != 0x60) {
		return
	}

	reader := &berReader{data: data, elements: 0}
	message := reader.read(0, len(data), 0)

	if _, isKnown := kerberosMessage[message.tag]; !isKnown || message.hasError() {
		return
	}

	body := message.first()

	if body == nil {
		return
	}

	// the pvno is the first field: [0] of a reply, an AP message or an error, [1] of a request
	for _, tag := range []int{0, 1} {
		if version, ok := body.context(tag).first().integer(data); ok && (version == 5) {
			score = 90
			return
		}
	}

	return
}

// one message: over TCP with its 4-byte length (the top bit is reserved and set only by an extension), over UDP the element alone
func kerberosFrame(data []byte, state *streamState) (length int) {
	if state.context.Transport != StreamTransport {
		length = berFrame(data, state)
		return
	}

	if len(data) < kerberosLengthBytes {
		return
	}

	if data[0]&0x80 != 0 {
		length = -1
		return
	}

	length = kerberosLengthBytes + int(uint32(data[0])<<24|uint32(data[1])<<16|uint32(data[2])<<8|uint32(data[3]))
	return
}

func kerberosPDU(tree *Tree, data []byte, start int, state *streamState) (root *node) {
	offset := start

	if state.context.Transport == StreamTransport {
		root = tree.add(nil, kerberosProtocol, kerberosTitle, "", start, len(data)-start)
		reader := fieldsOf(tree, root, data, start, min(len(data), start+kerberosLengthBytes))
		reader.number("kerberos.rm.length", "Record Mark", 4, nil)
		reader.finish()
		offset += kerberosLengthBytes
	}

	if offset >= len(data) {
		tree.addSummary("Kerberos record mark")
		return
	}

	reader := &berReader{data: data, elements: 0}
	message := reader.read(offset, len(data), 0)
	name := kerberosMessage[message.tag]

	if (message.class != applicationClass) || (name == "") {
		name = "unknown message"
	}

	body := message.first()
	fields := map[int]map[int]string{10: kerberosRequest, 12: kerberosRequest, 11: kerberosReply, 13: kerberosReply, 30: kerberosErrorTag, 14: kerberosAP, 15: kerberosAP}[message.tag]
	requestBody := body.contextOf(4)

	label := func(element *berElement, parent *berElement) (fieldName string, text string) {
		switch {
		case element == message:
			fieldName, text = kerberosProtocol+"."+name, name
		case (parent == body) && (element.class == contextClass) && (fields[element.tag] != ""):
			fieldName, text = kerberosProtocol+"."+fields[element.tag], fields[element.tag]
		case (requestBody != nil) && (parent == requestBody.first()) && (element.class == contextClass) && (kerberosBody[element.tag] != "") && ((message.tag == 10) || (message.tag == 12)):
			fieldName, text = kerberosProtocol+"."+kerberosBody[element.tag], kerberosBody[element.tag]
		}

		return
	}

	messageNode := berNodes(tree, root, data, message, label, nil)

	if root == nil {
		root = messageNode
		tree.setName(root, kerberosProtocol)
	}

	tree.setLabel(root, kerberosTitle+" ("+name+")")
	summary := "Kerberos " + name

	switch message.tag {
	case 10, 12:
		if requestBody := body.contextOf(4).first(); requestBody != nil {
			summary += kerberosNames(data, requestBody.context(2), requestBody.context(1), requestBody.context(3))
		}
	case 11, 13:
		summary += kerberosNames(data, body.contextOf(3), body.contextOf(4), nil)
	case 30:
		code, _ := body.contextOf(6).first().integer(data)
		summary += " " + shortName(kerberosErrors, uint16(code))
		summary += kerberosNames(data, body.contextOf(9), nil, body.contextOf(10))
	}

	tree.addSummary(summary)
	return
}

// the context child of an element that may be nil
func (element *berElement) contextOf(tag int) (child *berElement) {
	if element != nil {
		child = element.context(tag)
	}

	return
}

// realm, client and server name: a realm is [n] GeneralString, a PrincipalName [n] SEQUENCE { name-type [0], name-string [1] SEQUENCE OF }
func kerberosNames(data []byte, realm *berElement, client *berElement, server *berElement) (text string) {
	if realm := realm.first(); realm != nil {
		text += " realm " + textValue(realm.contents(data))
	}

	for _, principal := range []struct {
		label   string
		element *berElement
	}{{"cname", client}, {"sname", server}} {
		parts := principal.element.first().contextOf(1).first()

		if parts == nil {
			continue
		}

		name := ""

		for index, part := range parts.children {
			if index > 0 {
				name += "/"
			}

			name += string(part.contents(data))
		}

		text += " " + principal.label + " " + textValue([]byte(name))
	}

	return
}
