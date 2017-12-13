package main

import (
	"fmt"

	"custom_type"
)

func main() {
	var ff custom_type.FourField

	ff.First = 12

	fmt.Println(ff.First)
}
