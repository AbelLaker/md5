package md5

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"testing"
)

func TestLoad(t *testing.T) {
	h := md5.New()
	m := New()
	h.Write([]byte("12345"))
	h.Write([]byte("67890"))

	m.Write([]byte("12345"))
	d, err := json.Marshal(m)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(d))
	m2 := NewByJason(string(d))
	m2.Write([]byte("67890"))
	strh := fmt.Sprintf("%x", h.Sum(nil))
	strm := fmt.Sprintf("%x", m2.Sum(nil))
	if strh != strm {
		fmt.Println("hmd5 != strm :", strh, "!=", strm)
	} else {
		fmt.Println("hmd5 = strm :", strh)
	}

}
