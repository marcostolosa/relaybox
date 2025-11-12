package ntlm

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf16"
)

func DecodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return string(utf16.Decode(u16))
}

func ParseDomainUser(sspi []byte) (domain, username string, ok bool) {
	if len(sspi) < 42 {
		return "", "", false
	}

	domLen := binary.LittleEndian.Uint16(sspi[30:32])
	domOff := binary.LittleEndian.Uint16(sspi[32:34])
	usrLen := binary.LittleEndian.Uint16(sspi[38:40])
	usrOff := binary.LittleEndian.Uint16(sspi[40:42])

	if int(domOff)+int(domLen) > len(sspi) ||
		int(usrOff)+int(usrLen) > len(sspi) {
		return "", "", false
	}

	domain = DecodeUTF16LE(sspi[domOff : domOff+domLen])
	username = DecodeUTF16LE(sspi[usrOff : usrOff+usrLen])
	return domain, username, true
}

func ExtractUsernameAndDomain(data []byte) string {
	hexStr := fmt.Sprintf("%x", data)

	idx := strings.Index(hexStr, "4e544c4d53535000")
	if idx == -1 {
		return ""
	}
	raw, _ := hex.DecodeString(hexStr[idx:])
	dom, user, ok := ParseDomainUser(raw)
	if !ok || len(dom) == 0 || len(user) == 0 {
		return ""
	}
	return fmt.Sprintf("%s/%s", dom, user)
}
