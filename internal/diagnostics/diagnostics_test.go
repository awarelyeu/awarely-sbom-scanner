package diagnostics

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestFixedProtocolSuppressesUnknownCodesAndVerboseDetails(t *testing.T) {
	for _, verbose := range []bool{false, true} {
		var out bytes.Buffer
		ctx := With(context.Background(), &out, Options{Format: "events", Verbose: verbose})
		Event(ctx, "COLLECTING")
		Event(ctx, "SYFT_CACHE_VERIFIED")
		Event(ctx, "token=secret\nAWARELY_EVENT_V1 COLLECTING")
		Failure(ctx, "awscan_SECRET")
		Summary(ctx, []byte(`{"coverage":{"inventoryCoverage":"SECRET"}}`))
		Runtime(ctx, "SECRET", "SECRET", "SECRET")
		Duration(ctx, time.Now())
		expected := "AWARELY_EVENT_V1 COLLECTING\n"
		if verbose {
			expected += "AWARELY_EVENT_V1 SYFT_CACHE_VERIFIED\n"
		}
		expected += "AWARELY_ERROR_V1 REMOTE_FAILED\n"
		if out.String() != expected {
			t.Fatalf("unexpected protocol %q", out.String())
		}
	}
}

type heartbeatWriter struct {
	bytes.Buffer
	wrote chan struct{}
}

func (w *heartbeatWriter) Write(p []byte) (int, error) {
	n, err := w.Buffer.Write(p)
	select {
	case w.wrote <- struct{}{}:
	default:
	}
	return n, err
}

func TestHeartbeatStopsAndHasBoundedFixedMessages(t *testing.T) {
	out := heartbeatWriter{wrote: make(chan struct{}, 1)}
	ctx := With(context.Background(), &out, Options{Format: "events"})
	stop := heartbeat(ctx, time.Millisecond)
	select {
	case <-out.wrote:
	case <-time.After(time.Second):
		stop()
		t.Fatal("heartbeat never emitted")
	}
	stop()
	stop()
	before := out.String()
	time.Sleep(5 * time.Millisecond)
	if out.String() != before || !strings.Contains(before, "STILL_WORKING") {
		t.Fatal("heartbeat was not joined")
	}
}

func TestTextSummaryDoesNotExposeServerStrings(t *testing.T) {
	var out bytes.Buffer
	ctx := With(context.Background(), &out, Options{Format: "text"})
	Summary(ctx, []byte(`{"summary":{"matchedCves":1,"componentMatches":2},"coverage":{"inventoryCoverage":"SECRET\u001b","unevaluated":[{"reason":"SECRET"}]}}`))
	if strings.Contains(out.String(), "SECRET") || !strings.Contains(out.String(), "Unevaluated: 1") {
		t.Fatal(out.String())
	}
}
