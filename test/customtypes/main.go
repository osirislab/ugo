package main

import (
	"fmt"
	"reflect"
)

type Custom struct {
	hello string
}

func main() {
	var c Custom

	c.hello = "Hello"

	fmt.Println(c.hello)

	fmt.Println(reflect.TypeOf(c))
}
