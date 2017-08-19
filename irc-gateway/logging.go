package main

import "fmt"

type LogType int

var LogRune = map[LogType]string{
	DEBUG: "*",
	WARN:  "!",
	OK:    "✓",
}

const (
	DEBUG LogType = iota
	WARN
	OK
)

func Log(lt LogType, format string, args ...interface{}) {
	fmt.Printf("[%s] %s\n", LogRune[lt], fmt.Sprintf(format, args...))
}
