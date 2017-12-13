package main

import "fmt"

type Car struct {
	wheelCount int
}

func (car Car) numberOfWheels() int {
	return car.wheelCount
}

type Ferrari struct {
	Car
}

// a behavior only available for the Ferrari
func (f Ferrari) sayHiToSchumacher() {
	fmt.Println("Hi Schumacher!")
	fmt.Println(f.numberOfWheels())
}

type AstonMartin struct {
	Car
}

// a behavior only available for the AstonMartin
func (a AstonMartin) sayHiToBond() {
	fmt.Println("Hi Bond, James Bond!")
	fmt.Println(a.numberOfWheels())
}

func main() {
	f := Ferrari{Car{4}}
	fmt.Println("A Ferrari has this many wheels: ", f.numberOfWheels()) //has car behavior
	f.sayHiToSchumacher()                                               //has Ferrari behavior

	a := AstonMartin{Car{4}}
	fmt.Println("An Aston Martin has this many wheels: ", a.numberOfWheels()) //has car behavior
	a.sayHiToBond()                                                           //has AstonMartin behavior
}
