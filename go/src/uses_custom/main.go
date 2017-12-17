package main

import (
	"fmt"

	"custom_type"
)

func hello(a int) int {
  defer func() {
    fmt.Println("ok")
  }()
	fmt.Println(a)

	return 27
}

func main() {
	var ff custom_type.FourField

	ff.First = 12

  x := hello(12)
  fmt.Println(x)

	fmt.Println(ff.First)
}
