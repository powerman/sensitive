// go run _examples/basic/main.go mypassword
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/powerman/sensitive"
)

func main() {
	sensitive.Redact()

	password := sensitive.New(os.Args[1]) // Ref[string]

	fmt.Printf("%s\n", password)
	fmt.Printf("%v\n", password)

	b, _ := json.Marshal(password)
	fmt.Println(string(b))

	// output:
	// REDACTED
	// REDACTED
	// "REDACTED"
}
