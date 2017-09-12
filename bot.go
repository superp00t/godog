package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	"encoding/json"

	"strings"

	csay "github.com/dhruvbird/go-cowsay"
	"github.com/go-xorm/xorm"
	"github.com/gorilla/mux"
	"github.com/ogier/pflag"
	"github.com/olekukonko/tablewriter"
	"github.com/superp00t/godog/phoxy"

	_ "github.com/go-sql-driver/mysql"
)

var (
	DB *xorm.Engine
)

func main() {
	ap := pflag.StringP("api_key", "a", "admin", "the API key for use with the Phoxy administration API")

	name := pflag.StringP("name", "n", "harambe", "username")
	driver := pflag.StringP("driver", "r", "mysql", "SQL driver")
	db := pflag.StringP("db", "d", "", "SQL database")

	mainCD := pflag.BoolP("maincd", "m", false, "connect to the standard XMPP BOSH server")
	logEvents := pflag.BoolP("log_events", "l", false, "log Phoxy events")
	api := pflag.StringP("http_listen", "h", "", "spin up HTTP management server")
	msg := pflag.StringP("msg", "s", "", "greeting message")

	pflag.Parse()

	opts := []phoxy.Opts{
		{phoxy.PHOXY, *name, "lobby", "https://ikrypto.club/phoxy/", *ap, "", "", false},
		{phoxy.BOSH, *name, "lobby", "https://crypto.dog/http-bind/", *ap, "", "", false},
	}

	if *db != "" {
		var err error
		DB, err = xorm.NewEngine(*driver, *db)
		if err != nil {
			log.Fatal(err)
		}

		err = DB.Sync2(new(phoxy.Event))
		if err != nil {
			log.Fatal(err)
		}
	}

	if *api != "" {
		go func() {
			r := mux.NewRouter()

			r.HandleFunc("/messages", func(rw http.ResponseWriter, r *http.Request) {
				enc := json.NewEncoder(rw)
				p := r.URL.Query()
				if p.Get("fmt") == "yes" {
					enc.SetIndent("", "    ")
				}
				var ev []phoxy.Event

				// q := DB.Where("body REGEXP ?", p.Get("r"))

				err := DB.Find(&ev)
				if err != nil {
					log.Println(err)
				}
				enc.Encode(ev)
			})

			log.Fatal(http.ListenAndServe(*api, r))
		}()
	}

	sel := 0
	if *mainCD {
		sel = 1
	}

	b, err := phoxy.New(&opts[sel])
	if err != nil {
		log.Fatal(err)
	}

	if *logEvents {
		if DB == nil {
			log.Fatal("You need to supply a database to log events.")
		}
		b.Intercept(traceEvent)
	}

	start := time.Now()
	cmd := NewCmdParser()
	topic := "No topic yet"
	unAuthMsg := "You are not authorized to perform this action."

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

	cmd.Add("interrupt", "interrupt all connections from a user's IP", func(c *CmdCall) string {
		if !b.IsAuthorized(b.Opts.Chatroom, c.From) {
			return unAuthMsg
		}

		if len(c.Args) < 1 {
			return "usage: ipban <username>"
		}

		b.Interrupt(b.Opts.Chatroom, c.Args[0])
		return ""
	})

	cmd.Add("clearjail", "clear server IP jail", func(c *CmdCall) string {
		if !b.IsAuthorized(b.Opts.Chatroom, c.From) {
			return unAuthMsg
		}

		b.ClearJail()
		return "jail cleared."
	})

	cmd.Add("lockdown", "sets the lockdown level (1 to require captcha, 2 for registered users only)", func(c *CmdCall) string {
		if len(c.Args) == 0 {
			return "usage: lockdown <level>"
		}
		if b.IsAuthorized(b.Opts.Chatroom, c.From) {
			b.Lockdown(b.Opts.Chatroom, c.Args[0])
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

	cmd.Add("set_topic", "sets the topic", func(c *CmdCall) string {
		if b.AccessLevel(b.Opts.Chatroom, c.From) < 2 {
			return unAuthMsg
		}

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
		u, err := url.Parse("https://ikrypto.club/quotes/api/quotes")
		if err != nil {
			panic(err)
		}

		if len(c.Args) > 0 {
			q := u.Query()
			q.Set("q", c.Args[0])
			u.RawQuery = q.Encode()
		}

		r, err := http.Get(u.String())
		if err != nil {
			return ""
		}
		var q []Quote
		json.NewDecoder(r.Body).Decode(&q)
		rand.Seed(time.Now().Unix())
		if len(q) == 0 {
			return "no quote found"
		}
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

	cmd.Add("chmod", "chmod <user> <level>", func(c *CmdCall) string {
		acs := b.AccessLevel(b.Opts.Chatroom, c.From)
		if len(c.Args) == 1 {
			acs2 := b.AccessLevel(b.Opts.Chatroom, c.Args[0])
			return fmt.Sprintf("%s's access level is currently %d", c.Args[0], acs2)
		}

		if len(c.Args) == 2 {
			if acs < 6 {
				return unAuthMsg
			}

			if err := b.Chmod(b.Opts.Chatroom, c.Args[0], c.Args[1]); err != nil {
				return "chmod unsuccessful."
			}
		} else {
			return "usage: chmod <user> <level>"
		}
		return ""
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

	b.HandleFunc(phoxy.GROUPMESSAGE, func(ev *phoxy.Event) {
		t := time.Now()
		fmt.Printf("[%d:%d:%d]\t<%s>\t%s\n", t.Hour(), t.Minute(), t.Second(), ev.Username, ev.Body)

		if ev.Body == "." {
			b.GroupMessage(".")
			return
		}

		u, err := url.Parse(ev.Body)
		if err == nil {
			if u.Host == "www.youtube.com" {
				var resp noEmbedResp
				err := getJSON("https://noembed.com/embed", map[string]string{"url": u.String()}, &resp)
				if err == nil {
					b.Groupf("\"%s\" by %s", resp.Title, resp.Author)
				}
			}
		}

		msg := cmd.Parse(false, ev.Username, ev.Body)
		if msg != "" {
			b.GroupMessage(msg)
		}
	})

	b.HandleFunc(phoxy.USERJOIN, func(ev *phoxy.Event) {
		if ev.Username == b.Opts.Username {
			return
		}

		// Don't bother currently logged in users
		if start.UnixNano() > (time.Now().UnixNano() - (10 * time.Second).Nanoseconds()) {
			return
		}

		dur := 4000 * time.Millisecond
		time.Sleep(dur)
		if *msg != "" {
			b.GroupMessage(*msg)
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

type noEmbedResp struct {
	Title  string `json:"title"`
	Author string `json:"author_name"`
}

func traceEvent(ev *phoxy.Event) {
	if DB != nil {
		DB.Insert(ev)
	}
}

func getJSON(uri string, queryP map[string]string, v interface{}) error {
	if len(queryP) != 0 {
		p, err := url.Parse(uri)
		if err != nil {
			return err
		}

		q := p.Query()
		for k, v := range queryP {
			q.Set(k, v)
		}
		p.RawQuery = q.Encode()
		uri = p.String()
	}

	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 6.1; rv:31.0) Gecko/20100101 Firefox/31.0")
	client := &http.Client{}
	r, err := client.Do(req)
	if err != nil {
		return err
	}

	if r.StatusCode != 200 {
		return fmt.Errorf("Server returned %d", r.StatusCode)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r.Body)
	return json.Unmarshal(buf.Bytes(), &v)
}
