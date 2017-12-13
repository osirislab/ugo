package main

import (
	"fmt"
	"reflect"
)

func jesuschrist(arg1 int, arg2 int) (int, int) {
	return arg1 + arg2, arg1 * arg2
}

func main() {
	asdf := reflect.ValueOf(jesuschrist)
	fmt.Println(asdf.Type())
	fmt.Println(asdf.Type().NumIn())
	fmt.Println(asdf.Type().In(0))
}
