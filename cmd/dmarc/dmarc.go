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

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

var (
	dmarc *log.Logger
)

// SimpleEmailDisposition disposition return for SES
type SimpleEmailDisposition struct {
	Disposition string `json:"disposition"`
}

func init() {
	dmarc = log.New(os.Stdout,
		"[DMARC]: ",
		log.Ldate|log.Ltime,
	)
}

func main() {
	lambda.Start(HandleRequest)
}

// HandleRequest function that the lambda runtime service calls
func HandleRequest(ctx context.Context, event events.SimpleEmailEvent) (SimpleEmailDisposition, error) {
	return CheckDMARC(event, os.Getenv("DMARC_BLOCK_MODE") == "BLOCK"), nil
}

// CheckDMARC This is split out from HandleRequest for unit testing purproses so the tests do not have to figure out how to
// work with environment variables
func CheckDMARC(event events.SimpleEmailEvent, blockDmarc bool) SimpleEmailDisposition {

	// Default is assume this mail is compliant
	disposition := "STOP_RULE"
	for _, eventRecord := range event.Records {
		// If DMARC checks failed, log the DKIM and SPF status. If block mode is on, stop the rule set
		if eventRecord.SES.Receipt.DMARCVerdict.Status == "FAIL" {
			if blockDmarc {
				disposition = "CONTINUE"
				dmarc.Printf("MessageID=%s STATUS=BLOCK: SPF=%v DKIM=%v", eventRecord.SES.Mail.MessageID, eventRecord.SES.Receipt.SPFVerdict, eventRecord.SES.Receipt.DKIMVerdict)
			} else {
				dmarc.Printf("MessageID=%s STATUS=MONITOR: SPF=%v DKIM=%v", eventRecord.SES.Mail.MessageID, eventRecord.SES.Receipt.SPFVerdict, eventRecord.SES.Receipt.DKIMVerdict)
			}
		} else {
			dmarc.Printf("MessageID=%s STATUS=PASS: SPF=%v DKIM=%v", eventRecord.SES.Mail.MessageID, eventRecord.SES.Receipt.SPFVerdict, eventRecord.SES.Receipt.DKIMVerdict)
		}
	}

	return SimpleEmailDisposition{
		Disposition: disposition,
	}
}
