package main

import (
	"fmt"
	"strings"
)

type Frame struct {
	Notice  string
	Auth    string
	Shit    string
	Message string
}

type UserFrame struct {
	Name2, Name3 string
	Host         string
	Name4        string
}

func getFrame(input []string, c int) string {
	if c > len(input) {
		return ""
	}

	return input[c]
}
func DeserializeUserFrame(input string) *UserFrame {
	dob := strings.Split(input, " ")
	c := &UserFrame{
		Name2: getFrame(dob, 1),
		Name3: getFrame(dob, 2),
		Host:  getFrame(dob, 3),
		Name4: getFrame(dob, 4),
	}
	return c
}

func (f *Frame) SerializeToString() string {
	return fmt.Sprintf("%s %s %s %s\n", f.Notice, f.Auth, f.Shit, f.Message)
}

func (f *Frame) Serialize() []byte {
	return []byte(f.SerializeToString())
}
