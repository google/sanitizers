package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"io/ioutil"

	"golang.org/x/net/html"
)

func attr(n *html.Node, attrName string) string {
	for _, a := range n.Attr {
		if a.Key == attrName {
			return a.Val
		}
	}
	return ""
}

func class(n *html.Node) string {
	return attr(n, "class")
}

func findSubtag(n *html.Node, tagName string) *html.Node {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Data == tagName {
			return c
		}
	}

	return nil
}

func findSubtags(n *html.Node, tagName string) []*html.Node {
	result := make([]*html.Node, 0)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Data == tagName {
			result = append(result, c)
		}
	}
	return result
}

type status struct {
	buildUrl string
	rev      int64
	success  bool
}

type statusLine struct {
	date     string
	statuses []status
}

func GetStatus(buildUrl string) (statusLine, error) {
	if buildUrl == "" {
		return *new(statusLine), nil
	}

	var resp *http.Response
	var err error
	for i := 0; i < 3; i++ {
		client := http.Client{
			Timeout: time.Duration(120 * time.Second),
		}
		resp, err = client.Get(buildUrl + "?numbuilds=31")
		if err == nil {
			break
		}
	}

	if err != nil {
		return *new(statusLine), err
	}

	baseUrl, err := url.Parse(buildUrl)
	if err != nil {
		return *new(statusLine), err
	}

	doc, err := html.Parse(resp.Body)
	var f func(*html.Node) statusLine
	f = func(n *html.Node) statusLine {
		if n.Type == html.ElementNode && n.Data == "table" && class(n) == "info" {
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if c.Type == html.ElementNode && c.Data == "tbody" {
					date := ""
					var statuses []status
					for i, c := range findSubtags(c, "tr") {
						// ignore header row
						if i == 0 {
							// Does this look like the right table?
							h := findSubtag(c, "th")
							if h != nil && h.FirstChild != nil && h.FirstChild.Data == "Time" {
								continue
							}
							return *new(statusLine)
						}

						success := false
						buildUrl := ""
						var rev int64 = 0

						for i, c := range findSubtags(c, "td") {
							if i == 0 && date == "" {
								date = c.FirstChild.Data
							}
							if i == 1 {
								rev, _ = strconv.ParseInt(c.FirstChild.Data, 10, 0)
							}
							if i == 2 {
								success = class(c) == "success"
							}
							if i == 3 {
								relUrl, err := url.Parse(attr(findSubtag(c, "a"), "href"))
								if err == nil {
									buildUrl = baseUrl.ResolveReference(relUrl).String()
								}
							}
						}

						statuses = append(statuses, status{buildUrl, rev, success})
					}
					return statusLine{date, statuses}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if s := f(c); s.date != "" {
				return s
			}
		}
		return *new(statusLine)
	}

	return f(doc), err
}

type OssFuzzStatus struct {
	Projects    []string `json:"projects"`
	Successes   []string `json:"successes"`
	Failures    []string `json:"failures"`
	LastUpdated string   `json:"last_updated"`
}

func GetOssFuzzStatusString() string {
	header := "<h2>OSS-Fuzz</h2>"

	var resp *http.Response
	var err error
	for i := 0; i < 3; i++ {
		client := http.Client{
			Timeout: time.Duration(120 * time.Second),
		}
		resp, err = client.Get("https://oss-fuzz-build-logs.storage.googleapis.com/status.json")
		if err == nil {
			break
		}
	}

	if err != nil {
		return fmt.Sprintf("%s<p><span class=error>%v</span></p>", header, err)
	}

	var status OssFuzzStatus
	jsonBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Sprintf("%s<p><span class=error>%v</span></p>", header, err)
	}

	err = json.Unmarshal(jsonBytes, &status)
	if err != nil {
		return fmt.Sprintf("%s<p><span class=error>%v</span></p>", header, err)
	}

	htmlStatuses := ""
	sort.Strings(status.Projects)
	for i := range status.Projects {
		class := "success"
		for j := range status.Failures {
			if status.Failures[j] == status.Projects[i] {
				class = "error"
			}
		}
		htmlStatuses += fmt.Sprintf("<span class=%s>%s&nbsp;</span> ", class, status.Projects[i])
	}

	return fmt.Sprintf("%s %s", header, htmlStatuses)
}

func main() {
	bots := []struct {
		name, url string
	}{
		{"Clang", ""},
		{"(FYI) clang-x86_64-debian-fast", "http://lab.llvm.org:8011/builders/clang-x86_64-debian-fast"},
		{"Chromium", ""},
		{"(FYI) Clang Linux ToT", "https://build.chromium.org/p/chromium.fyi/builders/ClangToTLinux%20tester"},
		{"CFI Linux", "https://build.chromium.org/p/chromium.fyi/builders/CFI%20Linux"},
		{"CFI Linux ToT", "https://build.chromium.org/p/chromium.fyi/builders/CFI%20Linux%20ToT"},
		{"CFI Linux CF", "https://build.chromium.org/p/chromium.fyi/builders/CFI%20Linux%20CF"},
		{"Sanitizers", ""},
		{"sanitizer-windows", "http://lab.llvm.org:8011/builders/sanitizer-windows"},
		{"sanitizer-x86_64-linux", "http://lab.llvm.org:8011/builders/sanitizer-x86_64-linux"},
		{"sanitizer-x86_64-linux-bootstrap", "http://lab.llvm.org:8011/builders/sanitizer-x86_64-linux-bootstrap"},
		{"sanitizer-x86_64-linux-fast", "http://lab.llvm.org:8011/builders/sanitizer-x86_64-linux-fast"},
		{"sanitizer-x86_64-linux-autoconf", "http://lab.llvm.org:8011/builders/sanitizer-x86_64-linux-autoconf"},
		{"sanitizer-ppc64be-linux", "http://lab.llvm.org:8011/builders/sanitizer-ppc64be-linux"},
		{"sanitizer-ppc64le-linux", "http://lab.llvm.org:8011/builders/sanitizer-ppc64le-linux"},
		{"LibFuzzer", ""},
		{"sanitizer-x86_64-linux-fuzzer", "http://lab.llvm.org:8011/builders/sanitizer-x86_64-linux-fuzzer"},
		{"chromium-x86_64-linux-fuzzer-asan", "https://build.chromium.org/p/chromium.fyi/builders/Libfuzzer%20Upload%20Linux%20ASan"},
		{"chromium-x86_64-linux-fuzzer-asan-dbg", "https://build.chromium.org/p/chromium.fyi/builders/Libfuzzer%20Upload%20Linux%20ASan%20Debug"},
		{"chromium-x86_64-linux-fuzzer-msan", "https://build.chromium.org/p/chromium.fyi/builders/Libfuzzer%20Upload%20Linux%20MSan"},
		{"chromium-x86_64-linux-fuzzer-ubsan", "https://build.chromium.org/p/chromium.fyi/builders/Libfuzzer%20Upload%20Linux%20UBSan"},
	}

	statuses := make([]statusLine, len(bots))
	errors := make([]error, len(bots))
	type status_ret struct {
		n    int
		line statusLine
		err  error
	}
	status_ch := make(chan status_ret)
	for i := range bots {
		go func(i int) {
			s, err := GetStatus(bots[i].url)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
			status_ch <- status_ret{i, s, err}
		}(i)
	}

	maxStatuses := 0
	for range bots {
		status := <-status_ch
		statuses[status.n] = status.line
		errors[status.n] = status.err
		if maxStatuses < len(status.line.statuses) {
			maxStatuses = len(status.line.statuses)
		}
	}
	ossfuzz_ch := make(chan string)
	go func() { ossfuzz_ch <- GetOssFuzzStatusString() }()

	fmt.Println(`
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
   "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<title>dashboard</title>
<link href="https://fonts.googleapis.com/css?family=Open+Sans" rel="stylesheet">
<meta http-equiv="Content-Type" content="text/html;charset=utf-8">
<meta http-equiv="refresh" content="300">
<style type="text/css">
body { color: white; font-family: 'Open Sans', sans-serif; font-size: 24px; }
a {	color: inherit; text-decoration: none; }
h2 { margin: .25em 0 0 0; font-size: 110%; }
.error { color: red; }
.success { color: green; }
.checkmarks { display: flex; justify-content: space-between; font-weight: bold; }
</style>
</head>
<body bgcolor=black>
<table>
`)
	for i := range bots {
		if bots[i].url == "" {
			fmt.Println("<tr><td colspan=3><h2>")
			fmt.Println(bots[i].name)
			fmt.Println("</h2></td><td></td></tr>")
			continue
		}
		tr := func(s string) string {
			return fmt.Sprintf("<tr>%s</tr>", s)
		}

		td := func(attrs string, s string) string {
			return fmt.Sprintf("<td %s>%s</td>", attrs, s)
		}

		font := func(color string, s string) string {
			return fmt.Sprintf("<font color=%s>%s</font>", color, s)
		}
		span := func(class string, s string) string {
			return fmt.Sprintf("<span class=%s>%s</span>", class, s)
		}

		a := func(url string, text string) string {
			return fmt.Sprintf("<a href=\"%s\" target=_top>%s</a>", url, text)
		}

		r := ""
		date := "??:??"
		if statuses[i].date != "" {
			date = statuses[i].date[len(statuses[i].date)-5:]
		}
		r += td("", date+"&nbsp;")

		color := "red"
		if len(statuses[i].statuses) > 0 && statuses[i].statuses[0].success {
			color = "green"
		}
		r += td("width=30%", font(color, a(bots[i].url, bots[i].name)))

		if errors[i] != nil {
			errStr := errors[i].Error()
			trim := strings.LastIndex(errStr, ":")
			if trim != -1 {
				errStr = errStr[trim+1:]
			}
			r += td(fmt.Sprintf("colspan=%d", maxStatuses), font("white", errStr))
		} else if statuses[i].date == "" {
			r += td("", font("white", "?"))
		} else {

			cell := ""
			for j := range statuses[i].statuses[:len(statuses[i].statuses)-1] {
				s := statuses[i].statuses[j]
				style := "error"
				text := "&#x2717;" // x sign
				if s.success {
					style = "success"
					text = "&#x2713;" //checkmark
				}
				// TODO: Make use of revisions
				// text = fmt.Sprintf("%d", s.rev - statuses[i].statuses[j+1].rev)
				text = a(s.buildUrl, text)
				cell += span(style, text)
			}
			r += td("width=70%", "<span class=checkmarks>"+cell+"</span>")
		}
		fmt.Println(tr(r))
	}
	fmt.Println(`
</table>`)
	fmt.Println(<-ossfuzz_ch)
	fmt.Println(`
<p><font size=".8em">go/dynamic-tools-dashboard
`)
	fmt.Println(time.Now().Format("Mon Jan 2 15:04:05 -0700 MST 2006"))
	fmt.Println(`
</font></p>
</body>
</html>
`)
}
