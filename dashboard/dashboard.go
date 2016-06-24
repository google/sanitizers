package main

import (
	"fmt"
	"golang.org/x/net/html"
	"net/http"
	"net/url"
	"time"
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

	client := http.Client{
		Timeout: time.Duration(60 * time.Second),
	}
	resp, err := client.Get(buildUrl + "?numbuilds=30")
	if err != nil {
		return *new(statusLine), nil
	}

	baseUrl, err := url.Parse(buildUrl)
	if err != nil {
		return *new(statusLine), nil
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
							continue
						}

						success := false
						buildUrl := ""

						for i, c := range findSubtags(c, "td") {
							if i == 0 && date == "" {
								date = c.FirstChild.Data
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

						statuses = append(statuses, status{buildUrl, success})
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

	return f(doc), nil
}

func main() {
	bots := []struct {
		name, url string
	}{
		{"Clang", ""},
		{"clang-x86_64-debian-fast", "http://lab.llvm.org:8011/builders/clang-x86_64-debian-fast"},
		{"CFI", ""},
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
		{"clang-cmake-armv7-a15-full", "http://lab.llvm.org:8011/builders/clang-cmake-armv7-a15-full"},
		{"clang-cmake-thumbv7-a15-full-sh", "http://lab.llvm.org:8011/builders/clang-cmake-thumbv7-a15-full-sh"},
		{"LibFuzzer", ""},
		{"sanitizer-x86_64-linux-fuzzer", "http://lab.llvm.org:8011/builders/sanitizer-x86_64-linux-fuzzer"},
		{"chromium-x86_64-linux-fuzzer-asan", "https://build.chromium.org/p/chromium.fyi/builders/Libfuzzer%20Upload%20Linux%20ASan"},
		{"chromium-x86_64-linux-fuzzer-asan-dbg", "https://build.chromium.org/p/chromium.fyi/builders/Libfuzzer%20Upload%20Linux%20ASan%20Debug"},
		{"chromium-x86_64-linux-fuzzer-msan", "https://build.chromium.org/p/chromium.fyi/builders/Libfuzzer%20Upload%20Linux%20MSan"},
		{"chromium-x86_64-linux-fuzzer-ubsan", "https://build.chromium.org/p/chromium.fyi/builders/Libfuzzer%20Upload%20Linux%20UBSan"},
	}

	statuses := make([]statusLine, len(bots))
	type status_ret struct {
		n    int
		line statusLine
	}
	status_ch := make(chan status_ret)
	for i := range bots {
		go func(i int) {
			s, err := GetStatus(bots[i].url)
			if err != nil {
				panic(err)
			}
			status_ch <- status_ret{i, s}
		}(i)
	}

	for range bots {
		status := <-status_ch
		statuses[status.n] = status.line
	}

	fmt.Println(`
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
   "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<title>dashboard</title>
<meta http-equiv="Content-Type" content="text/html;charset=utf-8">
<meta http-equiv="refresh" content="300">
<style type="text/css">
a {
	color: inherit;
	text-decoration: none;
}
</style>
</head>
<body bgcolor=black>
<table>
`)
	for i := range bots {
		if bots[i].url == "" {
			fmt.Println("<tr><td><font color=white face=arial size=5>")
			fmt.Println(bots[i].name)
			fmt.Println("</font></td><td></td></tr>")
			continue
		}
		fmt.Println("<tr><td><font color=white face=arial size=6>")
		if statuses[i].date == "" {
			fmt.Println("??:??<font color=red>")
		} else {
			fmt.Println(statuses[i].date[len(statuses[i].date)-5:])
			if statuses[i].statuses[0].success {
				fmt.Println("<font color=green>")
			} else {
				fmt.Println("<font color=red>")
			}
		}
		fmt.Println("<a href=\"" + bots[i].url + "\">")
		fmt.Println(bots[i].name)
		fmt.Println("</a></font></font></td>")
		if statuses[i].date == "" {
			fmt.Println("<td><font color=white face=arial size=6>&nbsp;?</font></td>")
		} else {
			for _, s := range statuses[i].statuses {
				color := "red"
				text := "&nbsp;&#x2717;" // x sign
				if s.success {
					color = "green"
					text = "&nbsp;&#x2713;" //checkmark
				}
				fmt.Printf("<td><font color=%s face=arial size=6><a href=\"%s\">%s</a></font></td>\n", color, s.buildUrl, text)
			}
		}
		fmt.Println("</tr>")
	}
	fmt.Println(`
</table>
<font color=white face=arial size=4>go/dynamic-tools-dashboard
`)
	fmt.Println(time.Now().Format("Mon Jan 2 15:04:05 -0700 MST 2006"))
	fmt.Println(`
</font>
</body>
</html>
`)
}
