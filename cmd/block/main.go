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
	blocklist *log.Logger

	block map[string]string
)

// SimpleEmailDisposition disposition return for SES
type SimpleEmailDisposition struct {
	Disposition string `json:"disposition"`
}

func init() {
	blocklist = log.New(os.Stdout,
		"[BLOCKLIST]: ",
		log.Ldate|log.Ltime,
	)

	// parse the block list out of the environment variable.  format is [$domain:$mode]
	// This part is the senstive part.  If the format is not correct, golang should panic and fail the startup of the lambda
	// This is ok as SES will retry inbound receipt rule sets for up to 4hrs. As long as there is proper alerting
	// to alert on lambda errors and it is fixed within that timeframe no dropped inbounds will occur
	block = make(map[string]string)
	rawBlockList := strings.Split(os.Getenv("BLOCK"), ",")
	for _, entry := range rawBlockList {
		blockEntry := strings.Split(entry, ":")
		block[blockEntry[0]] = blockEntry[1]
	}
}

func main() {
	lambda.Start(HandleRequest)
}

// HandleRequest function that the lambda runtime service calls
func HandleRequest(ctx context.Context, event events.SimpleEmailEvent) (SimpleEmailDisposition, error) {

	// Default is assume this mail is compliant
	disposition := "STOP_RULE"
	for _, eventRecord := range event.Records {
		// Here's the fun.  Do not know why From is a slice but whatevs.
		// Compare the from domain to the blocklist and log if there was a match. If the blocklist contained the domain of the from address, stop the rule set
		for _, from := range eventRecord.SES.Mail.CommonHeaders.From {
			fromDomain := strings.Split(from, "@")[1]
			domainBlockValue := block[fromDomain]
			if domainBlockValue != "" {
				blocklist.Printf("MessageID=%s fromDomain=%s was in the blocklist in mode=%s", eventRecord.SES.Mail.MessageID, fromDomain, domainBlockValue)
				if domainBlockValue == "BLOCK" {
					disposition = "CONTINUE"
				}
			}
		}
	}

	return SimpleEmailDisposition{
		Disposition: disposition,
	}, nil
}
