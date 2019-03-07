package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/fatih/color"
	//surf "gopkg.in/headzoo/surf.v1"
)

type ThreatCrowdIPResult struct {
	ResponseCode string `json:"response_code"`
	Resolutions  []struct {
		LastResolved string `json:"last_resolved"`
		Domain       string `json:"domain"`
	} `json:"resolutions"`
	Hashes     []string      `json:"hashes"`
	References []interface{} `json:"references"`
	Votes      int           `json:"votes"`
	Permalink  string        `json:"permalink"`
}

type ThreatCrowdDomainResult struct {
	ResponseCode string `json:"response_code"`
	Resolutions  []struct {
		LastResolved string `json:"last_resolved"`
		IPAddress    string `json:"ip_address"`
	} `json:"resolutions"`
	Hashes     []interface{} `json:"hashes"`
	Emails     []string      `json:"emails"`
	Subdomains []string      `json:"subdomains"`
	References []interface{} `json:"references"`
	Votes      int           `json:"votes"`
	Permalink  string        `json:"permalink"`
}

type WebTech struct {
	Name string `json:"name"`
	Icon string `json:"icon"`
}

func main() {
	var cmd, options string
	redc := color.New(color.FgHiRed, color.Bold)
	greenc := color.New(color.FgHiGreen, color.Bold)
	cyanc := color.New(color.FgCyan, color.Bold)
	yellowc := color.New(color.FgHiYellow, color.Bold)
	cyanc.Printf("Enter Domain/IP/URL : $ ")
	reader := bufio.NewReader(os.Stdin)
	cmd, _ = reader.ReadString('\n')
	cmd = strings.TrimSuffix(cmd, "\r\n")
	validIP := regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
	isIP := validIP.MatchString(cmd)
	options = ""
	if cmd != "" {
		scanner := bufio.NewScanner(os.Stdin)
		for options != "0" {
			redc.Println("________________________________")
			fmt.Println("")
			greenc.Println("1. Web Tech")
			greenc.Println("2. Whois")
			greenc.Println("3. DnsLookup")
			greenc.Println("4. Reverse DNS Lookup")
			greenc.Println("5. Port Scan")
			greenc.Println("6. Reverse IP Lookup")
			greenc.Println("7. Subdomain Search")
			greenc.Println("8. Print to PDF [In Progress]")
			greenc.Println("0. Quit")
			redc.Println("________________________________")
			yellowc.Printf("Select your option : ")
			scanner.Scan()
			redc.Println("________________________________")
			options = scanner.Text()
			//greenc.Println(options)

			switch options {
			case "1":
				var teq string
				cyanc.Println("______________________________________________________________")

				quote := fmt.Sprintf("%s Powered by", cmd)
				cyanc.Println(quote)
				cyanc.Println("______________________________________________________________")
				if !strings.HasPrefix(cmd, "https:") {
					teq = "https://" + cmd
				} else {
					teq = cmd
				}
				//fmt.Println("Webteh " + teq)
				getWebTechresult(teq)
			case "2":
				cyanc.Println("_______________________________________________________________")

				cyanc.Println("Whois")
				cyanc.Println("_______________________________________________________________")
				getwhoisresult(getdomainfromURL(cmd))
			case "3":
				cyanc.Println("_______________________________________________________________")

				cyanc.Println("DNS LookUp")
				cyanc.Println("_______________________________________________________________")
				getdnslookupresult(getdomainfromURL(cmd))
			case "4":
				cyanc.Println("_______________________________________________________________")

				cyanc.Println("Reverse DNS LookUp")
				cyanc.Println("_______________________________________________________________")
				if isIP {
					getreverseIPlookupresult(getdomainfromURL(cmd))
				}
			case "5":
				cyanc.Println("_______________________________________________________________")

				cyanc.Println("Port Scan")
				cyanc.Println("_______________________________________________________________")
				getportscanresult(getdomainfromURL(cmd))
			case "6":
				cyanc.Println("_______________________________________________________________")

				cyanc.Println("Reverse IP LookUp")
				cyanc.Println("_______________________________________________________________")

				getreverseIPlookupresult(getdomainfromURL(cmd))
			case "7":
				if isIP {
					cyanc.Println("______________________________________________________________")

					cyanc.Println("Sub Domains")
					cyanc.Println("______________________________________________________________")

					getipinfofromthreatcrowd("ip", getdomainfromURL(cmd))
				} else {
					getipinfofromthreatcrowd("domain", getdomainfromURL(cmd))
				}
			case "8":
				cyanc.Println("In progress coming SOOOOOON....")

			}
			//if cmd != "q" {
			//fmt.Println("Your text was: ", text)
			//}
		}

	}

}

func checkerr(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

func getdomainfromURL(url string) string {
	url = strings.Replace(url, "//", "", -1)
	url = strings.Replace(url, "www.", "", -1)
	if strings.HasPrefix(url, "http") {
		url = strings.Split(url, ":")[1]
	}
	return url
}

func getresultfromdnsdumpster() {
	bluec := color.New(color.FgBlue, color.Bold)
	var srcURL = fmt.Sprintf("https://dnsdumpster.com/")
	body := getResponse(srcURL, "GET")
	bluec.Println(string(body))
}

func getdnslookupresult(domain string) {
	bluec := color.New(color.FgBlue, color.Bold)
	var srcURL = fmt.Sprintf("https://api.hackertarget.com/dnslookup/?q=%s", domain)
	body := getResponse(srcURL, "GET")
	bluec.Println(string(body))
}

func getreversednsresult(ip string) {
	bluec := color.New(color.FgBlue, color.Bold)
	var srcURL = fmt.Sprintf("https://api.hackertarget.com/reversedns/?q=%s", ip)
	body := getResponse(srcURL, "GET")
	bluec.Println(string(body))
}

func getportscanresult(domain string) {
	bluec := color.New(color.FgBlue, color.Bold)
	var srcURL = fmt.Sprintf("https://api.hackertarget.com/nmap/?q=%s", domain)
	//fmt.Println(srcURL)
	body := getResponse(srcURL, "GET")
	bluec.Println(string(body))
}

func getwhoisresult(domain string) {
	bluec := color.New(color.FgBlue, color.Bold)
	var srcURL = fmt.Sprintf("https://api.hackertarget.com/whois/?q=%s", domain)
	body := getResponse(srcURL, "GET")
	bluec.Println(string(body))
}

func getreverseIPlookupresult(domain string) {
	bluec := color.New(color.FgBlue, color.Bold)
	var srcURL = fmt.Sprintf("https://api.hackertarget.com/reverseiplookup/?q=%s", domain)
	body := getResponse(srcURL, "GET")
	bluec.Println(string(body))
}

func getWebTechresult(domain string) {
	bluec := color.New(color.FgBlue, color.Bold)
	var srcURL = fmt.Sprintf("https://api.wappalyzer.com/lookup-basic/beta/?url=%s", domain)
	strctWebTechs := []WebTech{}
	body := getResponse(srcURL, "GET")
	//fmt.Println(string(body))
	json.Unmarshal(body, &strctWebTechs)
	//fmt.Println(len(strctWebTechs))
	for _, webtech := range strctWebTechs {
		bluec.Println(webtech.Name)

	}
}

func getResponse(srcURL, httpmethod string) []byte {
	client := &http.Client{}
	req, err := http.NewRequest(httpmethod, srcURL, nil)
	checkerr(err)
	resp, err := client.Do(req)
	checkerr(err)
	defer resp.Body.Close()

	bodybyte, err := ioutil.ReadAll(resp.Body)
	checkerr(err)
	return bodybyte
}

func getipinfofromthreatcrowd(reportype, searchval string) {
	bluec := color.New(color.FgBlue, color.Bold)
	crossout := color.New(color.CrossedOut, color.Bold)
	yellowc := color.New(color.FgHiYellow, color.Bold)

	var strctThreatCrowdIPResult ThreatCrowdIPResult
	var strctThreatCrowdDomainResult ThreatCrowdDomainResult
	srcURL := fmt.Sprintf("https://threatcrowd.org/searchApi/v2/%s/report/?%s=%s", reportype, reportype, searchval)
	//fmt.Println(srcURL)

	bodybyte := getResponse(srcURL, "GET")
	//fmt.Println(string(bodybyte))
	if strings.Compare(reportype, "domain") == 0 {
		json.Unmarshal(bodybyte, &strctThreatCrowdDomainResult)
		yellowc.Println("Last Resolved _____ IP Address___________________________________")
		if len(strctThreatCrowdDomainResult.Resolutions) > 0 {
			for i := 0; i < len(strctThreatCrowdDomainResult.Resolutions); i++ {
				bluec.Println(strctThreatCrowdDomainResult.Resolutions[i].LastResolved + " ----- " + strctThreatCrowdDomainResult.Resolutions[i].IPAddress)
			}
		}
		yellowc.Println("_________________________Emails___________________________________")
		if len(strctThreatCrowdDomainResult.Emails) > 0 {
			for i := 0; i < len(strctThreatCrowdDomainResult.Emails); i++ {
				bluec.Println(strctThreatCrowdDomainResult.Emails[i])
			}
		}
		yellowc.Println("_______________________Sub Domains_____________________________________")

		if len(strctThreatCrowdDomainResult.Subdomains) > 0 {
			for i := 0; i < len(strctThreatCrowdDomainResult.Subdomains); i++ {
				bluec.Println(strctThreatCrowdDomainResult.Subdomains[i])
			}
		}
		yellowc.Println("____________________________________________________________")

	} else if strings.Compare(reportype, "ip") == 0 {
		json.Unmarshal(bodybyte, &strctThreatCrowdIPResult)
		yellowc.Println("Last Resolved _____ IP Address___________________________________")
		if len(strctThreatCrowdIPResult.Resolutions) > 0 {
			for i := 0; i < len(strctThreatCrowdIPResult.Resolutions); i++ {
				crossout.Println(strctThreatCrowdIPResult.Resolutions[i].LastResolved + " ----- " + strctThreatCrowdIPResult.Resolutions[i].Domain)
			}
		}
		yellowc.Println("____________________________________________________________")

	}

}
