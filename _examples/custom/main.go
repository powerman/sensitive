// go run _examples/custom/main.go mypassword
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/powerman/sensitive"
)

func init() {
	// Override the default redaction. This drives String as well as
	// Ref[string]/Handle[string], since they all delegate to FormatStringFn.
	sensitive.FormatStringFn = func(s sensitive.String, f fmt.State, c rune) {
		switch c {
		default:
			sensitive.Format(f, c, "redacted")
		case 'v':
			sensitive.Format(f, c, string(s)[:4]+"*******")
		}
	}
}

func main() {
	password := sensitive.New(os.Args[1]) // Ref[string]

	fmt.Printf("%s\n", password)
	fmt.Printf("%v\n", password)

	b, _ := json.Marshal(password)
	fmt.Println(string(b))

	// output:
	// redacted
	// mypa*******
	// "mypa*******"
}
