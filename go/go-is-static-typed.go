package main

import (
	"fmt"
)

func main() {
	var x int = 0
	fmt.Printf("%T", x)
	//Error here
	x = x + 0.5
}
