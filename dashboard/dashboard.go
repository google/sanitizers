package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"io/ioutil"

	"golang.org/x/net/html"
)

var (
	bots = []string{
		"sanitizer-windows",
		"sanitizer-x86_64-linux",
		"sanitizer-x86_64-linux-bootstrap-asan",
		"sanitizer-x86_64-linux-bootstrap-cfi",
		"sanitizer-x86_64-linux-bootstrap-msan",
		"sanitizer-x86_64-linux-bootstrap-ubsan",
		"sanitizer-x86_64-linux-fast",
		"sanitizer-x86_64-linux-android",
		"sanitizer-x86_64-linux-qemu",
		"sanitizer-aarch64-linux",
		"sanitizer-aarch64-linux-bootstrap-asan",
		"sanitizer-aarch64-linux-bootstrap-cfi",
		"sanitizer-aarch64-linux-bootstrap-hwasan",
		"sanitizer-aarch64-linux-bootstrap-msan",
		"sanitizer-aarch64-linux-bootstrap-ubsan",
		"sanitizer-ppc64le-linux",
		"sanitizer-x86_64-linux-fuzzer",
		"sanitizer-aarch64-linux-fuzzer",
	}

	masters = []struct {
		isStaging bool
		name string
	}{
		{false, "buildbot"},
		{true, "staging"},
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
	Number   int    `json:"number"`
	BuildUrl string `json:"build_url"`
	Success  int    `json:"success"`
}

type statusLine struct {
	Lastbuild  time.Time `json:"lastbuild"`
	Statuses   []status  `json:"statuses"`
	BuilderUrl string    `json:"builder_url"`
	Lkgb       string    `json:"lkgb"`
	IsStaging  bool      `json:"is_staging"`
}

func countBuilds(cache map[string]statusLine) int {
	n := 0
	for _, sl := range cache {
		n += len(sl.Statuses)
	}
	return n
}

func loadCache(path string) map[string]statusLine {
	cache := make(map[string]statusLine)
	data, err := os.ReadFile(path)
	if err == nil {
		_ = json.Unmarshal(data, &cache)
	}
	fmt.Fprintf(os.Stderr, "Loaded %d builds from cache in %s\n", countBuilds(cache), path)
	return cache
}

func saveCache(path string, cache map[string]statusLine) {
	for k, sl := range cache {
		sort.SliceStable(sl.Statuses, func(i, j int) bool {
			return sl.Statuses[i].Number > sl.Statuses[j].Number
		})
		if len(sl.Statuses) > 1000 {
			sl.Statuses = sl.Statuses[:1000]
		}
		cache[k] = sl
	}
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return
	}
	if err := os.WriteFile(path, data, 0666); err == nil {
		fmt.Fprintf(os.Stderr, "Saved %d builds to cache in %s\n", countBuilds(cache), path)
	}
}

func mergeStatusLine(fresh, cached statusLine) statusLine {
	if fresh.Lastbuild.IsZero() {
		return cached
	}
	if cached.Lastbuild.IsZero() {
		return fresh
	}
	if fresh.BuilderUrl != cached.BuilderUrl {
		if cached.Lastbuild.After(fresh.Lastbuild) {
			return cached
		}
		return fresh
	}
	if cached.Lastbuild.After(fresh.Lastbuild) {
		fresh, cached = cached, fresh
	}
	seen := make(map[string]bool, len(fresh.Statuses))
	merged := make([]status, 0, len(fresh.Statuses)+len(cached.Statuses))
	for _, s := range fresh.Statuses {
		seen[s.BuildUrl] = true
		merged = append(merged, s)
	}
	for _, s := range cached.Statuses {
		if !seen[s.BuildUrl] {
			seen[s.BuildUrl] = true
			merged = append(merged, s)
		}
	}
	sort.SliceStable(merged, func(i, j int) bool {
		return merged[i].Number > merged[j].Number
	})
	fresh.Statuses = merged
	if fresh.Lkgb == "" {
		fresh.Lkgb = cached.Lkgb
	}
	return fresh
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

func AnyContains(lst []string, s string) bool {
	for _, v := range lst {
		if v == s {
			return true
		}
	}
	return false
}

func QueryJSONBuilds(url string) (*Builds, error) {
	var resp *http.Response
	var err error
	for i := 0; i < 3; i++ {
		client := http.Client{
			Timeout: time.Duration(120 * time.Second),
		}
		resp, err = client.Get(url)
		if err == nil {
			break
		}
	}

	if err != nil {
		return nil, err
	}

	var builds Builds
	defer resp.Body.Close()
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(bodyBytes, &builds)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse JS: %s\n", err.Error())
		return nil, err
	}
	sort.SliceStable(builds.Builds, func(i, j int) bool {
		return builds.Builds[i].Number > builds.Builds[j].Number
	})
	return &builds, nil
}

func GetStatusFromJson(builderUrl string) (statusLine, error) {
	baseUrl, err := url.Parse(builderUrl)
	if err != nil {
		return *new(statusLine), err
	}

	builds, err := QueryJSONBuilds(builderUrl + "/builds?limit=3&order=-number&property=reason")
	if err != nil {
		return *new(statusLine), err
	}

	var sl statusLine = statusLine{
		BuilderUrl: builderUrl,
	}
	lkgb := 0
	lkgbUrl := ""
	for _, b := range builds.Builds {
		if !b.Complete {
			continue
		}
		if AnyContains(b.Properties.Reason, "Force Build Form") {
			continue
		}

		builder, _ := url.Parse(fmt.Sprintf("../../../#/builders/%d", b.Builderid))
		sl.BuilderUrl = baseUrl.ResolveReference(builder).String()
		time := time.Unix(int64(b.CompleteAt), 0)
		if sl.Lastbuild.Before(time) {
			sl.Lastbuild = time
		}

		build, _ := url.Parse(fmt.Sprintf("../../../#/builders/%d/builds/%d", b.Builderid, b.Number))
		thisUrl := baseUrl.ResolveReference(build).String()

		success := 0
		if b.Results < 2 {
			success = 1
			if b.Number > lkgb {
				lkgb = b.Number
				lkgbUrl = thisUrl
			}
		} else if b.Results == 2 {
			success = -1
		}
		sl.Statuses = append(sl.Statuses, status{b.Number, thisUrl, success})
		if len(sl.Statuses) >= 30 {
			break
		}
	}
	if lkgb == 0 {
		lkgbBuilds, err := QueryJSONBuilds(builderUrl + "/builds?limit=3&order=-number&property=reason&results__lt=2")
		if err != nil {
			return sl, nil
		}
		for _, b := range lkgbBuilds.Builds {
			if AnyContains(b.Properties.Reason, "Force Build Form") {
				continue
			}
			if b.Number > lkgb {
				build, _ := url.Parse(fmt.Sprintf("../../../#/builders/%d/builds/%d", b.Builderid, b.Number))
				lkgbUrl = baseUrl.ResolveReference(build).String()
				lkgb = b.Number
			}
		}
	}
	if lkgbUrl != "" {
		sl.Lkgb = lkgbUrl
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

						statuses = append(statuses, status{0, buildUrl, success})
					}
					return statusLine{lastbuild, statuses, builderUrl, "", false}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if s := f(c); !s.Lastbuild.IsZero() {
				return s
			}
		}
		return *new(statusLine)
	}

	return f(doc), err
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

	cachePath := filepath.Join(os.TempDir(), "sanitizer-dashboard-cache.json")
	cache := loadCache(cachePath)

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
			var best_s statusLine
			var best_err error
			
			for _, instance := range masters {
				url := fmt.Sprintf("http://lab.llvm.org/%s/api/v2/builders/%s", instance.name, bots[i])
				s, err := GetStatus(url)
				s.IsStaging = instance.isStaging
				if err == nil && !s.Lastbuild.IsZero() && time.Now().Sub(s.Lastbuild).Hours() <= 24 {
					status_ch <- status_ret{i, s, err}
					return
				}
				if best_s.Lastbuild.IsZero() || (!s.Lastbuild.IsZero() && s.Lastbuild.After(best_s.Lastbuild)) {
					best_s = s
					best_err = err
				}
			}
			
			
			status_ch <- status_ret{i, best_s, best_err}
		}(i)
	}

	maxStatuses := 0
	for range bots {
		status := <-status_ch
		cached, hasCached := cache[bots[status.n]]
		if hasCached {
			status.line = mergeStatusLine(status.line, cached)
			if !status.line.Lastbuild.IsZero() {
				status.err = nil
			}
		}
		if !status.line.Lastbuild.IsZero() {
			cache[bots[status.n]] = status.line
		}
		statuses[status.n] = status.line
		errors[status.n] = status.err
		if maxStatuses < len(status.line.Statuses) {
			maxStatuses = len(status.line.Statuses)
		}
	}
	saveCache(cachePath, cache)
	if maxStatuses > 30 {
		maxStatuses = 30
	}

	for i := range bots {
		if !statuses[i].Lastbuild.IsZero() && time.Since(statuses[i].Lastbuild) > 7*24*time.Hour {
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
		if statuses[i].Lkgb != "" {
			medal := "&#129351;"
			if statuses[i].IsStaging {
				medal = "&#129352;"
			}
			r += td("", a(statuses[i].Lkgb, medal))
		} else {
			r += td("", "")
		}
		
		
		date := "??:??"
		if !statuses[i].Lastbuild.IsZero() {
			// Localize times to PST
			lastbuild := statuses[i].Lastbuild
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
		r += td("", date)

		style := class(0)
		if len(statuses[i].Statuses) > 0 {
			style = class(statuses[i].Statuses[0].Success)
		}

		r += td("", a(statuses[i].BuilderUrl, span(style, bots[i])))

		if errors[i] != nil {
			errStr := errors[i].Error()
			trim := strings.LastIndex(errStr, ":")
			if trim != -1 {
				errStr = errStr[trim+1:]
			}
			r += td(fmt.Sprintf("colspan=%d", maxStatuses+1), span(class(0), errStr))
		} else if !statuses[i].Lastbuild.IsZero() {
			displayStatuses := statuses[i].Statuses
			if len(displayStatuses) > 30 {
				displayStatuses = displayStatuses[:30]
			}
			for _, s := range displayStatuses {
				style := class(s.Success)
				r += td("", a(s.BuildUrl, span(style+" symbol", "")))
			}
		}
		fmt.Println(tr(r))
	}
	fmt.Println(`</table>`)
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
