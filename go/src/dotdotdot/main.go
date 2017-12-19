package main

import "fmt"

func dotdotdot(a ...interface{}) (n int) {

  fmt.Println(a...)

  return 5
}

func main() {
  fmt.Println("hello")


  dotdotdot("Hello", "Hi", "sup")
}