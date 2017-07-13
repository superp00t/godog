package main

import (
	"bytes"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os/exec"
	"sort"
	"sync"
	"time"

	"encoding/json"

	"strings"

	csay "github.com/dhruvbird/go-cowsay"
	"github.com/ogier/pflag"
	"github.com/olekukonko/tablewriter"
	"github.com/superp00t/godog/phoxy"
)

func main() {
	ap := pflag.StringP("api_key", "a", "admin", "the API key for use with the Phoxy administration API")
	pflag.Parse()

	joinedAt := make(map[string]int64)
	joinLock := new(sync.Mutex)

	b, err := phoxy.New(&phoxy.Opts{
		Username: "bot",
		Chatroom: "lobby",
		Endpoint: "https://ikrypto.club/phoxy/",
		APIKey:   *ap,
	})

	if err != nil {
		log.Fatal(err)
	}

	start := time.Now()
	cmd := NewCmdParser()
	topic := "No topic yet"

	cmd.Add("ban", "bans a user", func(from string, args []string) string {
		if len(args) < 1 {
			return "usage: .ban <username>"
		}

		targ := args[0]

		if b.IsAuthorized(b.Opts.Chatroom, from) {
			go func() {
				time.Sleep(1000 * time.Millisecond)
				b.Ban(b.Opts.Chatroom, targ)
			}()
			return fmt.Sprintf("%s has been banned.", targ)
		}

		return "You are not authorized to perform this action."
	})

	cmd.Add("fortune", "shows your fortune", func(from string, args []string) string {
		var respBuf bytes.Buffer
		c := exec.Command("fortune")
		c.Stdout = &respBuf
		c.Run()
		return respBuf.String()
	})

	cmd.Add("cleanup", "destroys recently connected users", func(from string, args []string) string {
		if b.IsAuthorized(b.Opts.Chatroom, from) {
			tn := time.Now().UnixNano()
			tenSeconds := (10 * time.Second).Nanoseconds()

			dn := 0
			for name, v := range joinedAt {
				dn++
				if v > (tn - tenSeconds) {
					b.Ban(b.Opts.Chatroom, name)
				}
			}

			return fmt.Sprintf("Cleaned up %d names.", dn)
		}

		return ""
	})

	cmd.Add("set_topic", "sets the topic", func(from string, args []string) string {
		top := strings.Join(args, " ")
		topic = top
		return fmt.Sprintf("topic set to \"%s\"", topic)
	})

	cmd.Add("uptime", "shows how much uptime this bot has", func(from string, args []string) string {
		return fmt.Sprintf("uptime: %v", time.Since(start))
	})

	cmd.Add("quote", "Selects a random quote from https://ikrypto.club/quotes/", func(from string, args []string) string {
		r, err := http.Get("https://ikrypto.club/quotes/api/quotes")
		if err != nil {
			return ""
		}
		var q []Quote
		json.NewDecoder(r.Body).Decode(&q)
		rand.Seed(time.Now().Unix())
		qe := q[rand.Intn(len(q))]
		return qe.Body
	})

	cmd.Add("cowsay", "the cow says stuff", func(from string, args []string) string {
		if len(args) == 0 {
			return "usage: .cowsay <text>"
		}

		txt := strings.Join(args, " ")
		return "```" + csay.Format(txt)
	})

	cmd.Add("help", "shows this message", func(from string, args []string) string {
		buf := new(bytes.Buffer)
		table := tablewriter.NewWriter(buf)
		table.SetHeader([]string{"Command", "Description"})
		table.SetBorder(false)

		var help [][]string
		var ids []string
		for cn, _ := range cmd.Cmds {
			ids = append(ids, cn)
		}

		sort.Strings(ids)

		for _, id := range ids {
			help = append(help, []string{id, cmd.Cmds[id].Description})
		}

		table.AppendBulk(help)
		table.Render()
		return "```" + buf.String()
	})

	b.HandleFunc("groupMessage", func(ev *phoxy.Event) {
		if ev.Body == "." {
			b.GroupMessage(".")
			return
		}

		msg := cmd.Parse(ev.Username, ev.Body)
		if msg != "" {
			b.GroupMessage(msg)
		}
	})

	b.HandleFunc("userJoin", func(ev *phoxy.Event) {
		if ev.Username == b.Opts.Username {
			return
		}
		log.Printf("User %s joined\n", ev.Username)
		// Don't annoy people when you join
		if time.Since(start) < (3 * time.Second) {
			return
		}

		joinLock.Lock()
		joinedAt[ev.Username] = time.Now().UnixNano()
		joinLock.Unlock()

		time.Sleep(1200 * time.Millisecond)
		b.Groupf("Hey, %s! The topic of this conversation is \"%s\"", ev.Username, topic)
	})

	err = b.Connect()
	log.Fatal("Error connecting,", err)
}

type Quote struct {
	Id         int64  `json:"id" xorm:"'id'"`
	Body       string `json:"body" xorm:"longtext 'body'"`
	Time       int64  `json:"time" xorm:"'time'"`
	TimeFormat string `json:"-" xorm:"-"`
}

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
