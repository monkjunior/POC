package main

import "fmt"

func init() {
	fmt.Println("Go will execute init func before run into main function")
}

func main() {
	fmt.Println("Main function is running")
}

func init() {
	fmt.Println("We can have multiple init functions")
}
