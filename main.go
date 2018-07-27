// Copyright 2018 Jonathan Monette
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package main

import (
	"context"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

var (
	// Info Logger
	Info *log.Logger
	// Warning Logger
	Warning *log.Logger
	// Error Logger
	Error *log.Logger
	// Spam logger
	Spam *log.Logger
	//Dmarc logger
	Dmarc *log.Logger
	//Blocklist logger
	Blocklist *log.Logger

	blocklist []string
)

func init() {

	Info = log.New(os.Stdout,
		"[INFO]: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Warning = log.New(os.Stdout,
		"[WARNING]: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Error = log.New(os.Stderr,
		"[ERROR]: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Spam = log.New(os.Stdout,
		"[SPAM]: ",
		log.Ldate|log.Ltime)

	Dmarc = log.New(os.Stdout,
		"[DMARC]: ",
		log.Ldate|log.Ltime)

	Blocklist = log.New(os.Stdout,
		"[BLOCKLIST]: ",
		log.Ldate|log.Ltime)

	blocklist = strings.Split(os.Getenv("BLOCKLIST"), ",")
}

func main() {
	lambda.Start(HandleRequest)
}

// HandleRequest function that the lambda runtime service calls
func HandleRequest(ctx context.Context, event events.SimpleEmailEvent) error {

	for _, eventRecord := range event.Records {
		if eventRecord.SES.Receipt.SpamVerdict.Status == "FAIL" {
			Spam.Printf("MessageID=%s was considered SPAM", eventRecord.SES.Mail.MessageID)
		}

		if eventRecord.SES.Receipt.VirusVerdict.Status == "FAIL" {
			Spam.Printf("MessageID=%s possibly contained a VIRUS", eventRecord.SES.Mail.MessageID)
		}

		if eventRecord.SES.Receipt.DKIMVerdict.Status == "FAIL" || eventRecord.SES.Receipt.SPFVerdict.Status == "FAIL" {
			Dmarc.Printf("MessageID=%s failed DMARC", eventRecord.SES.Mail.MessageID)
		}

		for _, from := range eventRecord.SES.Mail.CommonHeaders.From {
			fromDomain := strings.Split(from, "@")[1]
			if contains(blocklist, fromDomain) {
				Blocklist.Printf("MessageID=%s fromDomain=%s was in the blocklist", eventRecord.SES.Mail.MessageID, fromDomain)
			}
		}
	}

	return nil
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
