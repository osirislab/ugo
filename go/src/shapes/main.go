package main

import (
	"fmt"
)

type Square struct {
	x, y int
	name string
}

func printShape(s Square) {
	fmt.Println(s.x)
	fmt.Println(s.y)
	fmt.Println(s.name)
}

func main() {
	shape := Square{10, 10, "hello"}

	printShape(shape)
}
