package ctcrypto

import (
	"fmt"

	"github.com/cronokirby/safenum"
)

func main() {
	var x, y safenum.Nat
	x.SetUint64(4)
	m := safenum.ModulusFromBytes([]byte{13})
	y.SetBytes([]byte{0xFF})
	x.Exp(&x, &y, m)
	fmt.Println(x)
}
