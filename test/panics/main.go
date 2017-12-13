package main

import "fmt"

func reeeee() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println(r)
		}
	}()

	panic("rreeeeeeee")
}

func main() {

	go reeeee()

	for {
	}
}
