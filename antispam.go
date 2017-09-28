package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
	"sync"
	"time"
)

type URLPerSec struct {
	Count int64
	Time  *time.Time
}

func ClearURL() {
	go func() {
		time.Sleep(10 * time.Second)
		URLPerSecond.Range(func(s interface{}, ve interface{}) bool {
			v := ve.(*URLPerSec)
			if v.Time.UnixNano() < (time.Now().UnixNano() - (10 * time.Second).Nanoseconds()) {
				v.Count = 0
				t := time.Now()
				v.Time = &t
			}
			return true
		})
	}()
}

var URLPerSecond = new(sync.Map)

type SpamCfg struct {
	Full  []string `json:"full"`
	Regex []string `json:"regex"`

	ScoreLimit int `json:"score_limit"`
}

func IsSpam(from, input string) bool {
	start := time.Now()
	defer fmt.Println("Spam detection", time.Since(start))

	b, _ := ioutil.ReadFile("spam.json")
	var c SpamCfg
	json.Unmarshal(b, &c)

	spammyRunes := []rune("0123456789_")
	spamScore := 0
	for _, v := range []rune(input) {
		for _, v2 := range spammyRunes {
			if v == v2 {
				spamScore++
				break
			}
		}
	}

	if strings.Contains(input, "http") == false {
		if spamScore > c.ScoreLimit {
			return true
		}
	} else {
		var d *URLPerSec
		val, ok := URLPerSecond.Load(from)
		if ok {
			d = val.(*URLPerSec)
		} else {
			d = &URLPerSec{}
			URLPerSecond.Store(from, d)
		}

		d.Count++
		if d.Count > 5 {
			return true
		}
	}

	for _, v := range c.Full {
		if input == v {
			return true
		}
	}

	for _, v := range c.Regex {
		r := regexp.MustCompile(v)
		if r.MatchString(input) {
			return true
		}
	}

	return false
}
