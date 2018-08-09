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
	spam  *log.Logger
	virus *log.Logger
)

// SimpleEmailDisposition disposition return for SES
type SimpleEmailDisposition struct {
	Disposition string `json:"disposition"`
}

func init() {

	spam = log.New(os.Stdout,
		"[SPAM]: ",
		log.Ldate|log.Ltime,
	)

	virus = log.New(os.Stdout,
		"[VIRUS]: ",
		log.Ldate|log.Ltime,
	)
}

func main() {
	lambda.Start(HandleRequest)
}

// HandleRequest function that the lambda runtime service calls
func HandleRequest(ctx context.Context, event events.SimpleEmailEvent) (SimpleEmailDisposition, error) {

	return CheckSPAM(event, os.Getenv("SPAM_BLOCK_MODE") == "BLOCK", os.Getenv("VIRUS_BLOCK_MODE") == "BLOCK"), nil
}

// CheckSPAM This is split out from HandleRequest for unit testing purproses so the tests do not have to figure out how to
// work with environment variables
func CheckSPAM(event events.SimpleEmailEvent, blockSpam bool, blockVirus bool) SimpleEmailDisposition {

	// Default is assume this mail is compliant
	disposition := "STOP_RULE"
	for _, eventRecord := range event.Records {
		// If AWS has classified this mail as spam, log that this happened.  If block mode is on, stop the rule set
		if eventRecord.SES.Receipt.SpamVerdict.Status == "FAIL" {
			if blockSpam {
				disposition = "CONTINUE"
				spam.Printf("MessageID=%s STATUS=BLOCK", eventRecord.SES.Mail.MessageID)
			} else {
				spam.Printf("MessageID=%s STATUS=MONITOR", eventRecord.SES.Mail.MessageID)
			}
		} else {
			spam.Printf("MessageID=%s STATUS=PASS", eventRecord.SES.Mail.MessageID)
		}

		// If AWS has classified any attachments as containing viruses, log that this happened.  If block mode is on, stop the rule set
		if eventRecord.SES.Receipt.VirusVerdict.Status == "FAIL" {
			if blockVirus {
				disposition = "CONTINUE"
				virus.Printf("MessageID=%s STATUS=BLOCK", eventRecord.SES.Mail.MessageID)
			} else {
				virus.Printf("MessageID=%s STATUS=MONITOR", eventRecord.SES.Mail.MessageID)
			}
		} else {
			virus.Printf("MessageID=%s STATUS=PASS", eventRecord.SES.Mail.MessageID)
		}
	}
	return SimpleEmailDisposition{
		Disposition: disposition,
	}
}
