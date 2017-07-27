package main

import (
	"strings"
	"time"
)

type CmdFunc func(from string, args []string) string

type CmdParser struct {
	Cmds map[string]*CmdEntry
	Rate map[string]*time.Time
}

func NewCmdParser() *CmdParser {
	return &CmdParser{
		Cmds: make(map[string]*CmdEntry),
		Rate: make(map[string]*time.Time),
	}
}

type CmdEntry struct {
	Description string
	Func        *CmdFunc
}

func (th *CmdParser) Add(cmd, description string, fn CmdFunc) {
	th.Cmds[cmd] = &CmdEntry{
		Description: description,
		Func:        &fn,
	}
}

func (th *CmdParser) Parse(from string, cmd string) string {
	if strings.HasPrefix(cmd, ".") == false {
		return ""
	}

	t := time.Now()
	th.Rate[from] = &t

	cmd = strings.TrimLeft(cmd, ".")
	cmdarg := strings.Split(cmd, " ")
	if len(cmd) < 1 {
		return ""
	}

	cmdCmd := cmdarg[0]
	cmdArgs := []string{}
	if len(cmdarg) > 1 {
		cmdArgs = cmdarg[1:]
	}

	if cm := th.Cmds[cmdCmd]; cm != nil {
		c := *cm.Func
		return c(from, cmdArgs)
	}

	return ""
}
