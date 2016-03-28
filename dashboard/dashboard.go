package main

import (
	"fmt"
	"golang.org/x/net/html"
	"net/http"
	"time"
)

func class(n *html.Node) string {
	for _, a := range n.Attr {
		if a.Key == "class" {
			return a.Val
		}
	}
	return ""
}

type status struct {
	date     string
	statuses []string
}

func GetStatus(url string) (status, error) {
	if url == "" {
		return *new(status), nil
	}

	client := http.Client{
		Timeout: time.Duration(60 * time.Second),
	}
	resp, err := client.Get(url + "?numbuilds=30")
	if err != nil {
		return *new(status), nil
	}

	doc, err := html.Parse(resp.Body)
	var f func(*html.Node) status
	f = func(n *html.Node) status {
		if n.Type == html.ElementNode && n.Data == "table" && class(n) == "info" {
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if c.Type == html.ElementNode && c.Data == "tbody" {
					date := ""
					var statuses []string
					for c := c.FirstChild; c != nil; c = c.NextSibling {
						if c.Type == html.ElementNode && c.Data == "tr" {
							i := 0
							for c := c.FirstChild; c != nil; c = c.NextSibling {
								if c.Type == html.ElementNode && c.Data == "td" {
									i++
									if i == 1 && date == "" {
										date = c.FirstChild.Data
									}
									if i == 3 {
										statuses = append(statuses, class(c))
									}
								}
							}
						}
					}
					return status{date, statuses}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if s := f(c); s.date != "" {
				return s
			}
		}
		return *new(status)
	}

	return f(doc), nil
}

func main() {
	bots := []struct {
		name, url string
	}{
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
                {"chromium-x86_64-linux-fuzzer-msan", "https://build.chromium.org/p/chromium.fyi/builders/Libfuzzer%20Upload%20Linux%20MSan"},
                {"chromium-x86_64-linux-fuzzer-ubsan", "https://build.chromium.org/p/chromium.fyi/builders/Libfuzzer%20Upload%20Linux%20UBSan"},
	}

	statuses := make([]status, len(bots))
	type status_ret struct {
		n      int
		status status
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
		statuses[status.n] = status.status
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
			if statuses[i].statuses[0] == "success" {
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
				if s == "success" {
					fmt.Println("<td><font color=green face=arial size=6>&nbsp;&#x2713;</font></td>")
				} else {
					fmt.Println("<td><font color=red face=arial size=6>&nbsp;&#x2717;</font></td>")
				}
			}
		}
		fmt.Println("</tr>")
	}
	fmt.Println(`
</table>
<font color=white face=arial size=4>
`)
	fmt.Println(time.Now().Format("Mon Jan 2 15:04:05 -0700 MST 2006"))
	fmt.Println(`
</font>
</body>
</html>
`)
}
