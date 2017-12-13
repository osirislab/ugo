package main

import (
	"fmt"
)

func returnThree(a int) (int, int, int) {
	return a * a, a * a * a, a * 12
}

func main() {
	squared, cubed, _ := returnThree(2)

	fmt.Println(squared)
	fmt.Println(cubed)
}
