package main

import (
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

func TestSpamAndVirus(t *testing.T) {
	t.Run("Test SPAM/Virus Pass No Block", testSpamVirucFunc("PASS", "PASS", false, false, "STOP_RULE"))
	t.Run("Test SPAM/Virus Pass Block", testSpamVirucFunc("PASS", "PASS", true, true, "STOP_RULE"))

	t.Run("Test SPAM Pass and No Block and Virus Fail No Block", testSpamVirucFunc("PASS", "FAIL", false, false, "STOP_RULE"))
	t.Run("Test SPAM Pass and Block and Virus Fail No Block", testSpamVirucFunc("PASS", "FAIL", true, false, "STOP_RULE"))
	t.Run("Test SPAM Fail and No Block Virus Pass No Block", testSpamVirucFunc("FAIL", "PASS", false, false, "STOP_RULE"))
	t.Run("Test SPAM Fail and Block Virus Pass No Block", testSpamVirucFunc("FAIL", "PASS", true, false, "CONTINUE"))

	t.Run("Test SPAM Pass and No Block and Virus Fail Block", testSpamVirucFunc("PASS", "FAIL", false, true, "CONTINUE"))
	t.Run("Test SPAM Pass and Block and Virus Fail Block", testSpamVirucFunc("PASS", "FAIL", true, true, "CONTINUE"))
	t.Run("Test SPAM Fail and No Block Virus Pass BLock", testSpamVirucFunc("FAIL", "PASS", false, true, "STOP_RULE"))
	t.Run("Test SPAM Fail and Block Virus Pass Block", testSpamVirucFunc("FAIL", "PASS", true, true, "CONTINUE"))

	t.Run("Test SPAM/Virus Fail No Block", testSpamVirucFunc("FAIL", "FAIL", false, false, "STOP_RULE"))
	t.Run("Test SPAM/Virus Fail Block", testSpamVirucFunc("FAIL", "FAIL", true, true, "CONTINUE"))
}

func testSpamVirucFunc(spamTestStatus string, virusTestStatus string, blockSpam bool, blockVirus bool, expected string) func(*testing.T) {
	return func(t *testing.T) {
		spamVerdict := events.SimpleEmailVerdict{
			Status: spamTestStatus,
		}

		virusVerdict := events.SimpleEmailVerdict{
			Status: virusTestStatus,
		}

		receipt := events.SimpleEmailReceipt{
			SpamVerdict:  spamVerdict,
			VirusVerdict: virusVerdict,
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

		disposition := CheckSPAM(mail, blockSpam, blockVirus)
		if expected != disposition.Disposition {
			t.Errorf("%s(expected) == %s(actual)", expected, disposition.Disposition)
		}
	}
}
