package main

import (
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

func TestDmarc(t *testing.T) {
	t.Run("Test DMARC Pass No BLock", testDmarcFunc("PASS", false, "STOP_RULE"))
	t.Run("Test DMARC Pass BLock", testDmarcFunc("PASS", true, "STOP_RULE"))
	t.Run("Test DMARC Fail No BLock", testDmarcFunc("FAIL", false, "STOP_RULE"))
	t.Run("Test DMARC Fail BLock", testDmarcFunc("FAIL", true, "CONTINUE"))
}

func testDmarcFunc(testStatus string, block bool, expected string) func(*testing.T) {
	return func(t *testing.T) {
		verdict := events.SimpleEmailVerdict{
			Status: testStatus,
		}

		receipt := events.SimpleEmailReceipt{
			DMARCVerdict: verdict,
		}

		service := events.SimpleEmailService{
			Receipt: receipt,
		}

		record := events.SimpleEmailRecord{
			SES: service,
		}

		records := []events.SimpleEmailRecord{record}

		mail := events.SimpleEmailEvent{
			Records: records,
		}

		disposition := CheckDMARC(mail, block)
		if expected != disposition.Disposition {
			t.Errorf("%s(expected) == %s(actual)", expected, disposition.Disposition)
		}
	}
}
