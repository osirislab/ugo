package main

import (
  "fmt"
)

func doNothing(x string) string { return x }

func printString(x string) { fmt.Println(x) }

func printGeneric(x interface{}) { fmt.Println(x) }

func main() {
  x := "yeet"

  fmt.Println(x)

  x = doNothing(x)

  printString(x)

  printGeneric(x)
}





