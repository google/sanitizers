package main

import (
	"errors"
	"fmt"
	"golang.org/x/net/html"
	"net/http"
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
	resp, err := http.Get(url)
	if err != nil {
		return *new(status), err
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

	s := f(doc)
	if s.date == "" {
		return *new(status), errors.New("Could not find status in document")
	}
	return s, nil
}

func main() {
	bots := []struct {
		name, url string
	}{
		{"CFI Linux", "https://build.chromium.org/p/chromium.fyi/builders/CFI%20Linux"},
		{"CFI Linux ToT", "https://build.chromium.org/p/chromium.fyi/builders/CFI%20Linux%20ToT"},
		{"CFI Linux CF", "https://build.chromium.org/p/chromium.fyi/builders/CFI%20Linux%20CF"},
		{"sanitizer-windows", "http://lab.llvm.org:8011/builders/sanitizer-windows"},
		{"sanitizer-x86_64-linux", "http://lab.llvm.org:8011/builders/sanitizer-x86_64-linux"},
		{"sanitizer-x86_64-linux-bootstrap", "http://lab.llvm.org:8011/builders/sanitizer-x86_64-linux-bootstrap"},
		{"sanitizer-x86_64-linux-fast", "http://lab.llvm.org:8011/builders/sanitizer-x86_64-linux-fast"},
		{"sanitizer-x86_64-linux-autoconf", "http://lab.llvm.org:8011/builders/sanitizer-x86_64-linux-autoconf"},
		{"sanitizer-x86_64-linux-fuzzer", "http://lab.llvm.org:8011/builders/sanitizer-x86_64-linux-fuzzer"},
		{"sanitizer_x86_64-freebsd", "http://lab.llvm.org:8011/builders/sanitizer_x86_64-freebsd"},
		{"sanitizer-ppc64-linux1", "http://lab.llvm.org:8011/builders/sanitizer-ppc64-linux1"},
		{"sanitizer-ppc64le-linux", "http://lab.llvm.org:8011/builders/sanitizer-ppc64le-linux"},
		{"sanitizer-windows", "http://lab.llvm.org:8011/builders/sanitizer-windows"},
		{"clang-cmake-armv7-a15-full", "http://lab.llvm.org:8011/builders/clang-cmake-armv7-a15-full"},
		{"clang-cmake-thumbv7-a15-full-sh", "http://lab.llvm.org:8011/builders/clang-cmake-thumbv7-a15-full-sh"},
		{"clang-cmake-aarch64-full", "http://lab.llvm.org:8011/builders/clang-cmake-aarch64-full"},
		{"clang-cmake-aarch64-42vma", "http://lab.llvm.org:8011/builders/clang-cmake-aarch64-42vma"},
		{"clang-native-aarch64-full", "http://lab.llvm.org:8011/builders/clang-native-aarch64-full"},
		{"clang-cmake-mips", "http://lab.llvm.org:8011/builders/clang-cmake-mips"},
		{"clang-cmake-mipsel", "http://lab.llvm.org:8011/builders/clang-cmake-mipsel"},
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
<html>
<meta http-equiv="refresh" content="300">
<body bgcolor=black>
<table>
`)
	for i := range bots {
		fmt.Println("<tr><td><font color=white face=arial size=6>")
		fmt.Println(statuses[i].date[len(statuses[i].date)-5:])
		if statuses[i].statuses[0] == "success" {
			fmt.Println("<font color=green>")
		} else {
			fmt.Println("<font color=red>")
		}
		fmt.Println(bots[i].name)
		fmt.Println("</font></font></td><td>")
		for j := 1; j != len(statuses[i].statuses) && j != 5; j++ {
			if statuses[i].statuses[j] == "success" {
				fmt.Println("<font color=green face=arial size=6>&nbsp;&nbsp;&#x2713;</font>")
			} else {
				fmt.Println("<font color=red face=arial size=6>&nbsp;&nbsp;&#x2717;</font>")
			}
		}
		fmt.Println("</td></tr>")
	}
	fmt.Println(`
</table>
</body>
</html>
`)
}
