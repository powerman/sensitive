package main

import (
	"fmt"

	"github.com/powerman/sensitive"
)

// AccessToken is a nominal secret type backed by Handle.
type AccessToken struct {
	sensitive.Handle[string]
}

func NewAccessToken(v string) AccessToken {
	return AccessToken{sensitive.Make(v)}
}

func main() {
	a := NewAccessToken("tok_abc123")
	b := NewAccessToken("tok_abc123")
	c := NewAccessToken("tok_def456")

	// == compares by value.
	fmt.Println(a == b) // true
	fmt.Println(a == c) // false

	// Handle is a valid map key.
	m := map[AccessToken]int{a: 1, c: 2}
	fmt.Println(m[b]) // 1 — same value as a
	fmt.Println(m[c]) // 2

	// output:
	// true
	// false
	// 1
	// 2
}
