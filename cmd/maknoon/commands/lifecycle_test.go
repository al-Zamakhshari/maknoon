package commands

import (
	"os"
	"testing"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func TestPersistentPreRunE(t *testing.T) {
	// 1. Test Human Mode (Default)
	root := &cobra.Command{
		Use: "maknoon",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			SetupViper()
			err := InitEngine()
			if err != nil {
				return err
			}
			// Simulate interactive terminal for standard CLI runs
			GlobalContext.UI.Interactive = true
			return nil
		},
	}
	root.PersistentFlags().BoolVar(&JSONOutput, "json", false, "")

	// Reset env
	os.Unsetenv("MAKNOON_AGENT_MODE")
	os.Unsetenv("MAKNOON_JSON")
	viper.Reset()
	SetupViper()
	JSONOutput = false

	if err := root.PersistentPreRunE(root, nil); err != nil {
		t.Fatalf("InitEngine failed: %v", err)
	}

	if _, ok := GlobalContext.Engine.GetPolicy().(*crypto.HumanPolicy); !ok {
		t.Errorf("Expected HumanPolicy, got %T", GlobalContext.Engine.GetPolicy())
	}

	// 2. Test Agent Mode via Env
	os.Setenv("MAKNOON_AGENT_MODE", "1")
	defer os.Unsetenv("MAKNOON_AGENT_MODE")
	viper.Reset()
	SetupViper()

	if err := root.PersistentPreRunE(root, nil); err != nil {
		t.Fatalf("InitEngine failed: %v", err)
	}

	if _, ok := GlobalContext.Engine.GetPolicy().(*crypto.AgentPolicy); !ok {
		t.Errorf("Expected AgentPolicy, got %T", GlobalContext.Engine.GetPolicy())
	}
	
	if !JSONOutput {
		t.Error("Agent mode should implicitly enable JSON output")
	}
}

func TestAgentConfigProtectionIntegration(t *testing.T) {
	// Simulate an Agent trying to run 'config set'
	os.Setenv("MAKNOON_AGENT_MODE", "1")
	defer os.Unsetenv("MAKNOON_AGENT_MODE")
	viper.Reset()
	SetupViper()
	
	if err := InitEngine(); err != nil {
		t.Fatal(err)
	}
	
	cmd := ConfigCmd()
	cmd.SetArgs([]string{"set", "perf.concurrency", "100"})
	
	err := cmd.Execute()
	if err == nil {
		t.Error("Agent should not be allowed to modify config, but command succeeded")
	} else if _, ok := err.(*crypto.ErrPolicyViolation); !ok {
		t.Errorf("Expected ErrPolicyViolation, got %v", err)
	}
}
