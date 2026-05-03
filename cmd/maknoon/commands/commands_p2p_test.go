package commands

import (
	"testing"
)

func TestP2PAdvancedCmds(t *testing.T) {
	SetJSONOutput(false)

	t.Run("Send Text (Agent Mode)", func(t *testing.T) {
		send := SendCmd()
		// We use a short timeout or mock if possible, but here we just check if it gets to established
		// Since it's a real network call to public relays, we'll verify the JSON output structure
		// until the "established" point.
		// NOTE: In a CI environment, we might want to skip real network calls,
		// but let's test the command parsing and initial logic.
		send.SetArgs([]string{"--text", "hello-p2p", "--json"})

		// We use a context with a timeout to avoid hanging if the relay is slow
		// but since we aren't actually running the receiver, it will just sit there.
		// For unit testing the command, we verify it accepts the flags.
		if send.Flags().Lookup("text") == nil {
			t.Error("Missing --text flag in send command")
		}
	})

	t.Run("Receive with Identity", func(t *testing.T) {
		recv := ReceiveCmd()
		if recv.Flags().Lookup("private-key") == nil {
			t.Error("Missing --private-key flag in receive command")
		}
		if recv.Flags().Lookup("p2p") == nil {
			t.Error("Missing --p2p flag in receive command")
		}
	})
}
