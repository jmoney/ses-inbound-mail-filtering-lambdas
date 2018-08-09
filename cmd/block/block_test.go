package main

import (
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

func TestBlockMap(t *testing.T) {
	blockMap := BuildBlockMap("gmail.com:BLOCK,linkedin.com:MONITOR")

	t.Run("Test Gmail block", func(t *testing.T) {
		if blockMap["gmail.com"] != "BLOCK" {
			t.Errorf("gmail.com=%s", blockMap["gmail.com"])
		}
	})

	t.Run("Test linkedin monitor", func(t *testing.T) {
		if blockMap["linkedin.com"] != "MONITOR" {
			t.Errorf("linkedin.com=%s", blockMap["linkedin.com"])
		}
	})
}

func TestBlock(t *testing.T) {
	blockMap := BuildBlockMap("gmail.com:MONITOR,linkedin.com:BLOCK")
	t.Run("Test Gmail block", testBlockFunc("foo@gmail.com", blockMap, "STOP_RULE"))
	t.Run("Test Yahoo block", testBlockFunc("bar@yahoo.com", blockMap, "STOP_RULE"))
	t.Run("Test LinkedIn monitor", testBlockFunc("baz@linkedin.com", blockMap, "CONTINUE"))
	t.Run("Test VIA linkedin block", testBlockFunc("Foo Bar via LinkedIn <invitations@linkedin.com>", blockMap, "CONTINUE"))
	t.Run("Test bad parse", testBlockFunc("Mail Delivery System <MAILER-DAEMON>", blockMap, "STOP_RULE"))
}

func testBlockFunc(testFrom string, blockMap map[string]string, expected string) func(*testing.T) {
	return func(t *testing.T) {
		headers := events.SimpleEmailCommonHeaders{
			From: []string{testFrom},
		}
		message := events.SimpleEmailMessage{
			CommonHeaders: headers,
		}
		service := events.SimpleEmailService{
			Mail: message,
		}

		record := events.SimpleEmailRecord{
			SES: service,
		}

		records := []events.SimpleEmailRecord{record}

		mail := events.SimpleEmailEvent{
			Records: records,
		}

		disposition := CheckBlock(mail, blockMap)
		if expected != disposition.Disposition {
			t.Errorf("%s(expected) == %s(actual)", expected, disposition.Disposition)
		}
	}
}
