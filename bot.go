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
	"sync"
	"time"

	"encoding/json"

	"strings"

	csay "github.com/dhruvbird/go-cowsay"
	"github.com/dpatrie/urbandictionary"
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

	endpoint := pflag.StringP("endpoint", "e", "https://ikrypto.club/phoxy/", "connect to the standard XMPP BOSH server")
	logEvents := pflag.BoolP("log_events", "l", false, "log Phoxy events")
	bf := pflag.BoolP("be_filter", "b", false, "filter spam")
	api := pflag.StringP("http_listen", "h", "", "spin up HTTP management server")
	msg := pflag.StringP("msg", "s", "", "greeting message")

	pflag.Parse()
	protocol := phoxy.PHOXY
	if strings.HasSuffix(*endpoint, "http-bind/") {
		protocol = phoxy.BOSH
	}

	if strings.HasPrefix(*endpoint, "wss://") {
		protocol = phoxy.WS
	}
	opts := phoxy.Opts{
		Type:     protocol,
		Username: *name,
		Chatroom: "lobby",
		Endpoint: *endpoint,
		APIKey:   *ap,
		BeFilter: *bf,
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

	b, err := phoxy.New(&opts)
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
	color := "#000000"
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

		if b.AccessLevel(b.Opts.Chatroom, c.From) > 2 {
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
		if b.Opts.Type == phoxy.PHOXY && b.AccessLevel(b.Opts.Chatroom, c.From) < 2 {
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
		if b.AccessLevel(b.Opts.Chatroom, c.From) < 3 {
			return unAuthMsg
		}

		if len(c.Args) != 0 {
			return getRat(b, c.Args[0])
		}
		return getRat(b, "")
	})

	cmd.Add("urbandict", "Searches a term on the Urban Dictionary", func(c *CmdCall) string {
		if len(c.Args) == 0 {
			return "usage: urbandict <searchterm>"
		}

		searchterm := strings.Join(c.Args, " ")

		UDresponse, err := urbandictionary.Query(searchterm)
		if err != nil {
			return err.Error()
		}

		if len(UDresponse.Results) == 0 {
			return "No definition found"
		}

		return UDresponse.Results[0].Definition
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

	cmd.Add("set_color", "sets the bot's color", func(c *CmdCall) string {
		if len(c.Args) < 1 {
			return "usage: set_color <hex color>"
		}

		color = c.Args[0]
		b.SendColor(color)
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

	IsABot := make(map[string]bool)
	Rates := make(map[string]int64)
	BotL := new(sync.Mutex)
	go func() {
		for {
			time.Sleep(60 * time.Second)
			BotL.Lock()
			Rates = make(map[string]int64)
		}
	}()

	b.HandleFunc(phoxy.GROUPMESSAGE, func(ev *phoxy.Event) {
		t := time.Now()
		fmt.Printf("[%d:%d:%d]\t<%s>\t%s\n", t.Hour(), t.Minute(), t.Second(), ev.Username, ev.Body)

		// if IsSpam(ev.Body) {
		// 	b.Interrupt(b.Opts.Chatroom, ev.Username)
		// 	log.Println("Removing spam")
		// 	return
		// }
		BotL.Lock()
		Rates[ev.Username] += int64(len(ev.Body))
		if Rates[ev.Username] > 1000 {
			IsABot[ev.Username] = true
		}

		if strings.HasPrefix(ev.Body, "+bot") {
			IsABot[ev.Username] = true
		}

		if IsABot[ev.Username] {
			BotL.Unlock()
			return
		}

		BotL.Unlock()

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

	b.HandleFunc(phoxy.VERIFY, func(ev *phoxy.Event) {
		isp := IsSpam(ev.Username, ev.Body)
		ev.Callback <- !isp
		log.Println(ev.Body)
		log.Println("Is spam", isp)
		if isp {
			log.Println("Banning", ev.Username)
			b.Interrupt(b.Opts.Chatroom, ev.Username)
		}
	})

	b.HandleFunc(phoxy.USERJOIN, func(ev *phoxy.Event) {
		if ev.Username == b.Opts.Username {
			return
		}

		b.SendColor(color)
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
		b.Groupf("+bot Hey, %s! The topic of this conversation is %s", ev.Username, topic)
	})

	go func() {
		time.Sleep(5 * time.Second)
		b.GroupMessage("+bot")
	}()

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
	log.Println(uri)

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
	// log.Println(buf.String())
	return json.Unmarshal(buf.Bytes(), &v)
}
