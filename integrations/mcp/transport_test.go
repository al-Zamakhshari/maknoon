package main

import (
	"net/http/httptest"
	"testing"

	"github.com/mark3labs/mcp-go/server"
)

func TestTransportSSE(t *testing.T) {
	engine := setupTestEngine(t)
	s := createServer(engine)
	ts := httptest.NewServer(nil)
	defer ts.Close()

	sse := server.NewSSEServer(s, server.WithBaseURL(ts.URL))
	ts.Config.Handler = sse

	t.Logf("SSE server ready at %s", ts.URL)
	if len(s.ListTools()) == 0 {
		t.Error("No tools registered in SSE server")
	}
}
