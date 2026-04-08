package commands

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/a-khallaf/maknoon/pkg/crypto"
	"github.com/computerex/dlgo"
	"github.com/spf13/cobra"
)

const (
	modelURL  = "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf"
	modelName = "qwen2.5-0.5b-instruct-q4_k_m.gguf"
)

func AiCmd() *cobra.Command {
	var prompt string

	cmd := &cobra.Command{
		Use:   "ai",
		Short: "Interact with the local GenAI assistant (Experimental)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if prompt == "" {
				return fmt.Errorf("prompt required (use --prompt)")
			}

			modelPath, err := ensureModelDownloaded()
			if err != nil {
				return fmt.Errorf("failed to prepare model: %w", err)
			}

			fmt.Println("🤖 Initializing local LLM (Qwen 0.5B)...")
			model, err := dlgo.LoadLLM(modelPath)
			if err != nil {
				return fmt.Errorf("failed to load LLM: %w", err)
			}

			fmt.Printf("🧠 Generating response for: \"%s\"\n\n", prompt)
			response, err := model.Chat("", prompt)
			if err != nil {
				return fmt.Errorf("inference failed: %w", err)
			}

			fmt.Println(response)
			return nil
		},
	}

	cmd.Flags().StringVarP(&prompt, "prompt", "p", "", "The prompt to send to the AI")
	return cmd
}

func ensureModelDownloaded() (string, error) {
	home, _ := os.UserHomeDir()
	modelsDir := filepath.Join(home, crypto.MaknoonDir, "models")
	if err := os.MkdirAll(modelsDir, 0700); err != nil {
		return "", err
	}

	modelPath := filepath.Join(modelsDir, modelName)
	if _, err := os.Stat(modelPath); err == nil {
		return modelPath, nil
	}

	fmt.Printf("📥 Model not found. Downloading %s (~400MB)...\n", modelName)
	out, err := os.Create(modelPath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	resp, err := http.Get(modelURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad status: %s", resp.Status)
	}

	_, err = io.Copy(out, resp.Body)
	return modelPath, err
}
