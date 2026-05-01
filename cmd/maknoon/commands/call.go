package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/spf13/cobra"
)

func CallCmd() *cobra.Command {
	var addr string
	var argsStr string
	cmd := &cobra.Command{
		Use:   "call [tool_name]",
		Short: "Invoke an MCP tool on a running Maknoon agent via API",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			toolName := args[0]

			var arguments map[string]any
			if argsStr != "" {
				if err := json.Unmarshal([]byte(argsStr), &arguments); err != nil {
					return fmt.Errorf("invalid JSON arguments: %v", err)
				}
			}

			req := mcp.CallToolRequest{
				Params: mcp.CallToolParams{
					Name:      toolName,
					Arguments: arguments,
				},
			}

			data, _ := json.Marshal(req)
			resp, err := http.Post(fmt.Sprintf("http://%s/call", addr), "application/json", bytes.NewBuffer(data))
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				return fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
			}

			io.Copy(cmd.OutOrStdout(), resp.Body)
			return nil
		},
	}

	cmd.Flags().StringVar(&addr, "addr", "localhost:8080", "Address of the running Maknoon agent")
	cmd.Flags().StringVar(&argsStr, "args", "", "JSON string of tool arguments")
	return cmd
}
