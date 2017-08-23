package main

import (
	"bytes"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"sort"
	"strconv"
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
	mainCD := pflag.BoolP("maincd", "m", false, "connect to the standard XMPP BOSH server")
	name := pflag.StringP("name", "n", "harambe", "username")
	pflag.Parse()

	opts := []phoxy.Opts{
		{phoxy.PHOXY, *name, "lobby", "https://ikrypto.club/phoxy/", *ap, "", "", false},
		{phoxy.BOSH, *name, "lobby", "https://crypto.dog/http-bind/", *ap, "", "", false},
	}

	sel := 0
	if *mainCD {
		sel = 1
	}

	b, err := phoxy.New(&opts[sel])
	if err != nil {
		log.Fatal(err)
	}

	start := time.Now()
	cmd := NewCmdParser()
	topic := "No topic yet"
	unAuthMsg := "You are not authorized to perform this action"

	cmd.Add("ban", "bans a user", func(c *CmdCall) string {
		if len(c.Args) < 1 {
			return "usage: .ban <username>"
		}

		targ := c.Args[0]

		if b.IsAuthorized(b.Opts.Chatroom, c.From) {
			go func() {
				time.Sleep(1000 * time.Millisecond)
				b.Ban(b.Opts.Chatroom, targ)
			}()
			return fmt.Sprintf("%s has been banned.", targ)
		}

		return unAuthMsg
	})

	cmd.Add("lockdown", "prevents unlisted names from joining the chat", func(c *CmdCall) string {
		if b.IsAuthorized(b.Opts.Chatroom, c.From) {
			b.Lockdown(b.Opts.Chatroom)
			return ""
		}

		return unAuthMsg
	})

	cmd.Add("cleanup", "destroys recently connected users", func(c *CmdCall) string {
		if len(c.Args) < 1 {
			return "usage: .cleanup <seconds>"
		}

		if b.IsAuthorized(b.Opts.Chatroom, c.From) {
			ti, err := strconv.ParseInt(c.Args[0], 10, 64)
			if err != nil {
				return err.Error()
			}

			dn, err := b.Cleanup(b.Opts.Chatroom, ti)
			return fmt.Sprintf("Cleaned up %d names.", dn)
		}

		return unAuthMsg
	})

	cmd.Add("lockdown", "prevents new users from joining the room", func(c *CmdCall) string {
		if b.IsAuthorized(b.Opts.Chatroom, c.From) {
			b.Lockdown(b.Opts.Chatroom)
			return ""
		}

		return unAuthMsg
	})

	cmd.Add("set_topic", "sets the topic", func(c *CmdCall) string {
		top := strings.Join(c.Args, " ")
		topic = top
		return fmt.Sprintf("topic set to \"%s\"", topic)
	})

	cmd.Add("uptime", "shows how much uptime this bot has", func(c *CmdCall) string {
		return fmt.Sprintf("uptime: %v", time.Since(start))
	})

	// Fun functions
	cmd.Add("ratpost", "Queries a random rat from Reddit", func(c *CmdCall) string {
		return getRat(b)
	})

	cmd.Add("quote", "Selects a random quote from https://ikrypto.club/quotes/", func(c *CmdCall) string {
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

	cmd.Add("cowsay", "the cow says stuff", func(c *CmdCall) string {
		if len(c.Args) == 0 {
			return "usage: .cowsay <text>"
		}

		txt := strings.Join(c.Args, " ")
		return "```" + csay.Format(txt)
	})

	cmd.Add("help", "shows this message", func(c *CmdCall) string {
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
		t := time.Now()
		fmt.Printf("[%d:%d:%d]\t<%s>\t%s\n", t.Hour(), t.Minute(), t.Second(), ev.Username, ev.Body)

		if ev.Body == "." {
			b.GroupMessage(".")
			return
		}

		msg := cmd.Parse(false, ev.Username, ev.Body)
		if msg != "" {
			b.GroupMessage(msg)
		}
	})

	b.HandleFunc("userJoin", func(ev *phoxy.Event) {
		if ev.Username == b.Opts.Username {
			return
		}

		time.Sleep(1200 * time.Millisecond)

		// Don't bother currently logged in users
		if start.UnixNano() > (time.Now().UnixNano() - (10 * time.Second).Nanoseconds()) {
			return
		}

		b.Groupf("Hey, %s! The topic of this conversation is %s", ev.Username, topic)
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
