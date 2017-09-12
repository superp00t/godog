package main

import (
	crand "crypto/rand"
	"encoding/binary"
	"log"
	"math/rand"
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
	Data ratChildData `json"data"`
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
	for {
		buf := make([]byte, 8)
		crand.Read(buf)
		in := binary.LittleEndian.Uint64(buf)
		rng := rand.New(rand.NewSource(int64(in)))
		ratc := rats[rng.Intn(len(rats))]
		rat := ratc.Data.URL
		if alreadySent[rat] == true {
			continue
		}

		ext := filepath.Ext(rat)
		if (strings.HasPrefix(rat, "https://imgur.com") || ext == ".jpeg" || ext == ".jpg" || ext == ".png") == false {
			continue
		}

		alreadySent[rat] = true
		return rat
	}
}

func getRat(bot *phoxy.PhoxyConn) string {
	interval := time.Second * 40
	if timeOfLastRatQuery > time.Now().UnixNano()-(interval).Nanoseconds() {
		log.Println("Ratpost attempt is too recent")
		return getRandomRat()
	}

	timeOfLastRatQuery = time.Now().UnixNano()
	for {
		var rp ratPosts
		err := getJSON("https://www.reddit.com/r/RATS/top.json", nil, &rp)
		if err != nil {
			log.Println(err)
			continue
		}

		rats = rp.Data.Children
		break
	}

	return getRandomRat()
}
