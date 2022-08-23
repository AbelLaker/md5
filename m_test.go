package md5

import (
	"crypto/md5"
	"fmt"
	"testing"
)

func TestLoad(t *testing.T) {
	h := md5.New()
	m := New()
	str := fmt.Sprintf("%x", m.Sum(nil))
	fmt.Println("m md5:", str)
	str = fmt.Sprintf("%x", h.Sum(nil))
	fmt.Println("h md5:", str)
}
