// Command probe prints the release the linker embedded in internal/version. It is
// built by internal/version's test, with the same -X flag the release build uses.
package main

import (
	"fmt"

	"github.com/jeremyakers/askdo/internal/version"
)

func main() { fmt.Printf("%q\n", version.Release) }
