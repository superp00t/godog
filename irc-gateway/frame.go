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

func DeserializeUserFrame(input string) *UserFrame {
	dob := strings.Split(input, " ")
	return &UserFrame{
		Name2: dob[1],
		Name3: dob[2],
		Host:  dob[3],
		Name4: dob[4],
	}
}

func (f *Frame) SerializeToString() string {
	return fmt.Sprintf("%s %s %s %s\n", f.Notice, f.Auth, f.Shit, f.Message)
}

func (f *Frame) Serialize() []byte {
	return []byte(f.SerializeToString())
}
