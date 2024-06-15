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

var (
	bots = []struct {
		name, url string
	}{
		{"Sanitizers", ""},
		{"windows", "http://lab.llvm.org/buildbot/api/v2/builders/sanitizer-windows"},
		{"x86_64-linux", "http://lab.llvm.org/buildbot/api/v2/builders/sanitizer-x86_64-linux"},
		{"x86_64-linux-asan", "http://lab.llvm.org/buildbot/api/v2/builders/sanitizer-x86_64-linux-bootstrap-asan"},
		{"x86_64-linux-msan", "http://lab.llvm.org/buildbot/api/v2/builders/sanitizer-x86_64-linux-bootstrap-msan"},
		{"x86_64-linux-ubsan", "http://lab.llvm.org/buildbot/api/v2/builders/sanitizer-x86_64-linux-bootstrap-ubsan"},
		{"x86_64-linux-fast", "http://lab.llvm.org/buildbot/api/v2/builders/sanitizer-x86_64-linux-fast"},
		{"x86_64-linux-android", "http://lab.llvm.org/buildbot/api/v2/builders/sanitizer-x86_64-linux-android"},
		{"x86_64-linux-qemu", "http://lab.llvm.org/buildbot/api/v2/builders/sanitizer-x86_64-linux-qemu"},
		{"aarch64-linux", "http://lab.llvm.org/buildbot/api/v2/builders/sanitizer-aarch64-linux"},
		{"aarch64-linux-asan", "http://lab.llvm.org/buildbot/api/v2/builders/sanitizer-aarch64-linux-bootstrap-asan"},
		{"aarch64-linux-hwasan", "http://lab.llvm.org/buildbot/api/v2/builders/sanitizer-aarch64-linux-bootstrap-hwasan"},
		{"aarch64-linux-msan", "http://lab.llvm.org/buildbot/api/v2/builders/sanitizer-aarch64-linux-bootstrap-msan"},
		{"aarch64-linux-ubsan", "http://lab.llvm.org/buildbot/api/v2/builders/sanitizer-aarch64-linux-bootstrap-ubsan"},
		{"ppc64be-linux", "http://lab.llvm.org/buildbot/api/v2/builders/sanitizer-ppc64be-linux"},
		{"ppc64le-linux", "http://lab.llvm.org/buildbot/api/v2/builders/sanitizer-ppc64le-linux"},
		{"LibFuzzer", ""},
		{"x86_64-linux-fuzzer", "http://lab.llvm.org/buildbot/api/v2/builders/sanitizer-x86_64-linux-fuzzer"},
		{"aarch64-linux-fuzzer", "http://lab.llvm.org/buildbot/api/v2/builders/sanitizer-aarch64-linux-fuzzer"},
	}
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
	success  int
}

type statusLine struct {
	lastbuild  time.Time
	statuses   []status
	builderUrl string
}

type Builds struct {
	Builds []struct {
		Builderid  int  `json:"builderid"`
		Buildid    int  `json:"buildid"`
		Complete   bool `json:"complete"`
		CompleteAt int  `json:"complete_at"`
		Number     int  `json:"number"`
		Results    int  `json:"results"`
		Properties struct {
			Reason []string `json:"reason"`
		} `json:"properties"`
	} `json:"builds"`
}

func GetStatusFromJson(builderUrl string) (statusLine, error) {
	if builderUrl == "" {
		return *new(statusLine), nil
	}

	var resp *http.Response
	var err error
	for i := 0; i < 3; i++ {
		client := http.Client{
			Timeout: time.Duration(120 * time.Second),
		}
		resp, err = client.Get(builderUrl + "/builds?limit=40&order=-number&property=reason")
		if err == nil {
			break
		}
	}

	if err != nil {
		return *new(statusLine), err
	}

	baseUrl, err := url.Parse(builderUrl)
	if err != nil {
		return *new(statusLine), err
	}

	var builds Builds
	defer resp.Body.Close()
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(bodyBytes, &builds)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse JS: %s\n", err.Error())
		return *new(statusLine), err
	}
	sort.SliceStable(builds.Builds, func(i, j int) bool {
		return builds.Builds[i].Number > builds.Builds[j].Number
	})
	var sl statusLine = statusLine{
		builderUrl: builderUrl,
	}
	for _, b := range builds.Builds {
		if !b.Complete {
			continue
		}
		foundForceBuild := false
		for _, v := range b.Properties.Reason {
			if v == "Force Build Form" {
				foundForceBuild = true
				break
			}
		}
		if foundForceBuild {
			continue
		}

		builder, _ := url.Parse(fmt.Sprintf("../../../#/builders/%d", b.Builderid))
		sl.builderUrl = baseUrl.ResolveReference(builder).String()
		time := time.Unix(int64(b.CompleteAt), 0)
		if sl.lastbuild.Before(time) {
			sl.lastbuild = time
		}
		success := 0
		if b.Results < 2 {
			success = 1
		} else if b.Results == 2 {
			success = -1
		}
		build, _ := url.Parse(fmt.Sprintf("../../../#/builders/%d/builds/%d", b.Builderid, b.Number))
		sl.statuses = append(sl.statuses, status{baseUrl.ResolveReference(build).String(), success})
		if len(sl.statuses) >= 31 {
			break
		}
	}
	return sl, nil
}

func GetStatus(builderUrl string) (statusLine, error) {
	if builderUrl == "" {
		return *new(statusLine), nil
	}

	if strings.Contains(builderUrl, "lab.llvm.org") {
		return GetStatusFromJson(builderUrl)
	}

	var resp *http.Response
	var err error
	for i := 0; i < 3; i++ {
		client := http.Client{
			Timeout: time.Duration(120 * time.Second),
		}
		resp, err = client.Get(builderUrl + "?numbuilds=31")
		if err == nil {
			break
		}
	}

	if err != nil {
		return *new(statusLine), err
	}

	baseUrl, err := url.Parse(builderUrl)
	if err != nil {
		return *new(statusLine), err
	}

	doc, err := html.Parse(resp.Body)
	var f func(*html.Node) statusLine
	f = func(n *html.Node) statusLine {
		if n.Type == html.ElementNode && n.Data == "table" && class(n) == "info" {
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if c.Type == html.ElementNode && c.Data == "tbody" {
					lastbuild := time.Time{}
					var statuses []status
					isLuci := false
					for i, c := range findSubtags(c, "tr") {
						// ignore header row
						if i == 0 {
							// Does this look like the right table?
							h := findSubtag(c, "th")
							if h != nil && h.FirstChild != nil {
								if h.FirstChild.Data == "Time" {
									continue
								} else if h.FirstChild.Data == "Create time" {
									isLuci = true
									continue
								}
							}
							return *new(statusLine)
						}

						success := 0
						buildUrl := ""

						for i, c := range findSubtags(c, "td") {
							if ((!isLuci && i == 0) || (isLuci && i == 1)) && lastbuild.IsZero() {
								// LUCI has slightly different layout/formatting than buildbot
								if c.FirstChild.Data == "span" {
									strtime, err := strconv.ParseInt(attr(c.FirstChild, "data-timestamp"), 10, 64)
									if err == nil {
										lastbuild = time.Unix(strtime/1000, 0)
									}
								} else {
									loc, err := time.LoadLocation("America/Los_Angeles")
									if err == nil {
										parsedtime, err := time.ParseInLocation("Jan 2 15:04", c.FirstChild.Data, loc)
										if err == nil {
											lastbuild = parsedtime.AddDate(time.Now().Year(), 0, 0)
										} else {
											fmt.Fprintf(os.Stderr, "Failed to parse: %s\n", err.Error())
										}
									} else {
										fmt.Fprintf(os.Stderr, "Failed to load TZ: %s\n", err.Error())
									}
								}
							}
							if (!isLuci && i == 2) || (isLuci && i == 4) {
								classC := class(c)
								if strings.Contains(strings.ToLower(classC), "success") {
									success = 1
								}
								if strings.Contains(strings.ToLower(classC), "failure") {
									success = -1
								}
							}
							if (!isLuci && i == 3) || (isLuci && i == 5) {
								relUrl, err := url.Parse(attr(findSubtag(c, "a"), "href"))
								if err == nil {
									buildUrl = baseUrl.ResolveReference(relUrl).String()
								}
							}
						}

						statuses = append(statuses, status{buildUrl, success})
					}
					return statusLine{lastbuild, statuses, builderUrl}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if s := f(c); !s.lastbuild.IsZero() {
				return s
			}
		}
		return *new(statusLine)
	}

	return f(doc), err
}

type OssFuzzBuild struct {
	Success    bool `json:"success"`
}

type OssFuzzProject struct {
	Name    string `json:"name"`
	Builds []OssFuzzBuild `json:"history"`
}

type OssFuzzStatus struct {
	Projects    []OssFuzzProject
}

type ByName []OssFuzzProject

func (a ByName) Len() int           { return len(a) }
func (a ByName) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByName) Less(i, j int) bool { return a[i].Name < a[j].Name }

var OssFuzzOurProjects = map[string]bool{
	"fuzzing-puzzles":     true,
	"libpng-proto":        true,
	"libprotobuf-mutator": true,
	"llvm":                true,
	"llvm_libcxxabi":      true,
}

func GetOssFuzzStatusString() string {
	header := "<h2>OSS-Fuzz</h2>"

	var resp *http.Response
	var err error
	stausUrl := "https://oss-fuzz-build-logs.storage.googleapis.com"
	for i := 0; i < 3; i++ {
		client := http.Client{
			Timeout: time.Duration(120 * time.Second),
		}
		resp, err = client.Get(stausUrl + "/status.json")
		if err == nil {
			break
		}
	}

	if err != nil {
		return fmt.Sprintf("%s<p><span class=other>%v</span></p>", header, err)
	}

	var status OssFuzzStatus
	jsonBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Sprintf("%s<p><span class=other>%v</span></p>", header, err)
	}

	err = json.Unmarshal(jsonBytes, &status)
	if err != nil {
		return fmt.Sprintf("%s<p><span class=other>%v</span></p>", header, err)
	}

	htmlStatuses := ""
	sort.Sort(ByName(status.Projects))
	for i := range status.Projects {
		if !OssFuzzOurProjects[status.Projects[i].Name] {
			continue
		}
		class := "success"
		if len(status.Projects[i].Builds) > 0 && !status.Projects[i].Builds[0].Success {
			class = "error"
		}
		htmlStatuses += fmt.Sprintf(
			"<span class='%s'><a href='%s/index.html#%s'>%s</a>&nbsp;</span> ",
			class, stausUrl, status.Projects[i].Name, status.Projects[i].Name)
	}

	return fmt.Sprintf("%s %s", header, htmlStatuses)
}

func main() {
	fmt.Println(`
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
   "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<title>dashboard</title>
<link href="https://fonts.googleapis.com/css?family=Open+Sans|Inconsolata" rel="stylesheet">
<meta http-equiv="Content-Type" content="text/html;charset=utf-8">
<meta http-equiv="refresh" content="43200">
<style type="text/css">
body { color: white; font-family: 'Open Sans', sans-serif; font-size: 24px; }
a { color: inherit; text-decoration: none; }
h2 { margin: .25em 0 0 0; font-size: 110%; }
.error { color: red; }
.error.symbol::before { content: "\2717"; font-family: 'Inconsolata', monospace; font-weight: bold;}
.success { color: green; }
.success.symbol::before { content: "\2713"; font-family: 'Inconsolata', monospace; font-weight: bold;}
.warning { color: yellow; }
.warning.symbol::before {content: "?"; font-family: 'Inconsolata', monospace; font-weight: bold;}
.other { color: #c6c; }
.other.symbol::before { content: "~"; font-family: 'Inconsolata', monospace; font-weight: bold;}
table {
   width: 100%;
}
</style>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.1.1/jquery.min.js"></script>
<script>
// Reload without flickering.
$(function() {
  setTimeout(function() {
    $.get('', function(data) { $(document.body).html(data); });
  },60000);
});
</script>
</head>
<body bgcolor=black>
<table>
`)

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
			bots[i].url = s.builderUrl
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

	for i := range bots {
		if bots[i].url == "" {
			fmt.Println(fmt.Sprintf("<tr><td colspan=%d><h2>", maxStatuses+3))
			fmt.Println(bots[i].name)
			fmt.Println("</h2></td></tr>")
			continue
		}

		tr := func(s string) string {
			return fmt.Sprintf("<tr>%s</tr>", s)
		}

		td := func(attrs string, s string) string {
			return fmt.Sprintf("<td %s>%s</td>", attrs, s)
		}

		span := func(class string, s string) string {
			return fmt.Sprintf("<span class=\"%s\">%s</span>", class, s)
		}

		a := func(url string, text string) string {
			return fmt.Sprintf("<a href=\"%s\" target=_top>%s</a>", url, text)
		}

		class := func(status int) string {
			if status == 1 {
				return "success"
			} else if status == -1 {
				return "error"
			}
			return "other"
		}

		r := ""
		date := "??:??"
		if !statuses[i].lastbuild.IsZero() {
			// Localize times to PST
			lastbuild := statuses[i].lastbuild
			loc, err := time.LoadLocation("America/Los_Angeles")
			if err == nil {
				lastbuild = lastbuild.In(loc)
			}

			if time.Now().Sub(lastbuild).Hours() <= 12 {
				date = lastbuild.Format("15:04")
			} else {
				date = lastbuild.Format("<span class=other>Jan 2 15:04</span>")
			}
		}
		r += td("", date+"&nbsp;")

		style := class(0)
		if len(statuses[i].statuses) > 0 {
			style = class(statuses[i].statuses[0].success)
		}

		r += td("", a(bots[i].url, span(style, bots[i].name)))

		if errors[i] != nil {
			errStr := errors[i].Error()
			trim := strings.LastIndex(errStr, ":")
			if trim != -1 {
				errStr = errStr[trim+1:]
			}
			r += td(fmt.Sprintf("colspan=%d", maxStatuses+1), span(class(0), errStr))
		} else if !statuses[i].lastbuild.IsZero() {
			for j := range statuses[i].statuses[:len(statuses[i].statuses)-1] {
				s := statuses[i].statuses[j]
				style := class(s.success)
				r += td("", a(s.buildUrl, span(style+" symbol", "")))
			}
		}
		fmt.Println(tr(r))
	}
	fmt.Println(`</table>`)
	fmt.Println(<-ossfuzz_ch)
	fmt.Println(`<p><font size=".8em">go/dynamic-tools-dashboard, `)
	tz, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		fmt.Println("err: ", err.Error())
	}
	fmt.Println(time.Now().In(tz).Format("2006-Jan-2 15:04:05 MST"))
	fmt.Println(`
</font></p>
</body>
</html>
`)
}
