package main

import (
	"log"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/superp00t/godog/phoxy"
)

type ratChildData struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

type ratChild struct {
	Data ratChildData `json:"data"`
}

type ratData struct {
	Children []ratChild `json:"children"`
}

type ratPosts struct {
	Message string  `json:"message"`
	Error   int     `json:"error"`
	Data    ratData `json:"data"`
}

var rats []ratChild
var timeOfLastRatQuery int64
var alreadySent = make(map[string]bool)

func getRandomRat() string {
	errors := 0
	for _, v := range rats {
		if errors > 8 {
			return "No posts found"
		}

		rat := v.Data.URL
		if alreadySent[rat] == true {
			continue
		}

		ext := filepath.Ext(rat)
		p, err := url.Parse(rat)
		if err != nil {
			errors++
			continue
		}

		if (ext == "webm" || p.Host == "gfycat.com" || p.Host == "imgur.com" || p.Host == "i.reddit.com" || p.Host == "i.imgur.com" || ext == ".jpeg" || ext == ".jpg" || ext == ".png" || strings.HasSuffix(rat, "jpg") || strings.HasSuffix(rat, "jpeg") || strings.Contains(rat, "jpg?")) == false {
			errors++
			continue
		}

		log.Println(rat)

		alreadySent[rat] = true
		return rat
	}

	return "No valid posts found"
}

var lastSR string

func getRat(bot *phoxy.PhoxyConn, param string) string {
	reddit := "/r/RATS"
	if param != "" {
		reddit = "/r/" + param
	}
	interval := time.Second * 40

	if timeOfLastRatQuery > time.Now().UnixNano()-(interval).Nanoseconds() && lastSR == reddit {
		log.Println("Ratpost attempt is too recent")
		return getRandomRat()
	}

	lastSR = reddit

	timeOfLastRatQuery = time.Now().UnixNano()
	for {
		var rp ratPosts
		err := getJSON("https://www.reddit.com"+reddit+"/top.json", nil, &rp)
		if err != nil {
			log.Println(err)
			return err.Error()
		}

		if len(rp.Data.Children) == 0 {
			return "No posts found."
		}

		rats = rp.Data.Children
		break
	}

	return getRandomRat()
}
