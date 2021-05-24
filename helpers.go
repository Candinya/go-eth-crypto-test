package main

import (
	"bufio"
	"fmt"
	"strings"
)

func GetInput(notice string, r *bufio.Reader) string {

	fmt.Print(notice)
	input, _ := r.ReadString('\n')

	input = strings.Replace(input, "\r", "", -1)
	input = strings.Replace(input, "\n", "", -1)

	return input

}
