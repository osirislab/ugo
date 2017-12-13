package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
)

func div19(x float64) float64 {
	return x / 19.0
}

func div(a float64, b float64) float64 {
	return a / b
}

func main() {

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter a: ")
	text, _ := reader.ReadString('\n')
	x, _ := strconv.ParseFloat(text[:len(text)-1], 64)
	// fmt.Print("Enter b: ")
	// text, _ = reader.ReadString('\n')
	// y, _ := strconv.ParseFloat(text[:len(text)-1], 64)

	fmt.Println(div19(x))
}
