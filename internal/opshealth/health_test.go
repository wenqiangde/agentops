package opshealth

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wenqiangde/agentops/internal/opsconfig"
	"github.com/wenqiangde/agentops/internal/opsexec"
)

type fakeExecutor struct {
	requests []opsexec.Request
	result   opsexec.Result
}

func (e *fakeExecutor) Run(_ context.Context, r opsexec.Request) opsexec.Result {
	e.requests = append(e.requests, r)
	return e.result
}
func (e *fakeExecutor) Copy(context.Context, opsexec.CopyRequest) opsexec.Result {
	return opsexec.Result{}
}

func TestHealthHTTPAcceptsOnlyConfiguredStatuses(t *testing.T) {
	client := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	for _, tt := range []struct {
		name     string
		statuses []int
		healthy  bool
	}{{"accepted", []int{204}, true}, {"not configured", []int{200}, false}} {
		t.Run(tt.name, func(t *testing.T) {
			got := probeHTTP(context.Background(), nil, opsconfig.Environment{Kind: opsconfig.EnvironmentKindLocal}, opsconfig.Health{Type: "http", URL: "http://127.0.0.1/health", SuccessStatuses: tt.statuses}, time.Second, client)
			if got.Healthy != tt.healthy || got.StatusCode != 204 {
				t.Fatalf("result=%+v", got)
			}
		})
	}
}

func TestHealthRemoteHTTPUsesExplicitCurlArgvAndLocalStatusDecision(t *testing.T) {
	ex := &fakeExecutor{result: opsexec.Result{ExitCode: 0, Stdout: "302"}}
	got := Probe(context.Background(), ex, opsconfig.Environment{Kind: opsconfig.EnvironmentKindSSH, Host: "prod"}, opsconfig.Health{Type: "http", URL: "http://127.0.0.1/health", SuccessStatuses: []int{200}}, time.Second)
	want := []string{"--silent", "--show-error", "--output", "/dev/null", "--write-out", "%{http_code}", "--max-time", "1", "--", "http://127.0.0.1/health"}
	if got.Healthy || got.StatusCode != 302 || len(ex.requests) != 1 || ex.requests[0].Program != "curl" || !reflect.DeepEqual(ex.requests[0].Args, want) {
		t.Fatalf("result=%+v requests=%+v", got, ex.requests)
	}
}

func TestHealthCommandUsesStructuredExplicitArgv(t *testing.T) {
	secret := "credential-payload"
	ex := &fakeExecutor{result: opsexec.Result{ExitCode: 0, Stdout: secret}}
	health := opsconfig.Health{Type: "command", Command: &opsconfig.CommandProbe{Program: "php", Args: []string{"artisan", "health"}}}
	got := Probe(context.Background(), ex, opsconfig.Environment{}, health, time.Second)
	if !got.Healthy || len(ex.requests) != 1 || ex.requests[0].Program != "php" || !reflect.DeepEqual(ex.requests[0].Args, []string{"artisan", "health"}) {
		t.Fatalf("result=%+v requests=%+v", got, ex.requests)
	}
	if strings.Contains(got.Detail, secret) || got.Detail != "command succeeded (exit=0)" {
		t.Fatalf("unsafe detail=%q", got.Detail)
	}
	ex.result = opsexec.Result{ExitCode: 7, Stdout: secret}
	got = Probe(context.Background(), ex, opsconfig.Environment{}, health, time.Second)
	if got.Healthy || got.Detail != "command failed (exit=7)" || strings.Contains(got.Detail, secret) {
		t.Fatalf("unsafe failure=%+v", got)
	}
}

func TestHealthProcessRejectsInvalidPIDBeforeKill(t *testing.T) {
	for _, output := range []string{"", "0", "-1", "1 2", "abc", "999999999999999999999999"} {
		ex := &fakeExecutor{result: opsexec.Result{ExitCode: 0, Stdout: output}}
		got := Probe(context.Background(), ex, opsconfig.Environment{PIDFile: "/tmp/demo.pid"}, opsconfig.Health{Type: "process"}, time.Second)
		if got.Healthy || got.Err == nil || len(ex.requests) != 1 {
			t.Fatalf("output=%q result=%+v requests=%+v", output, got, ex.requests)
		}
	}
}

func TestHealthRemoteHTTPValidatesURLAndPreservesTimeoutPrecision(t *testing.T) {
	invalid := []string{"-option", "ftp://example.com/health", "http://user:secret@example.com/health", "http:///missing-host"}
	for _, raw := range invalid {
		ex := &fakeExecutor{}
		got := Probe(context.Background(), ex, opsconfig.Environment{Kind: opsconfig.EnvironmentKindSSH, Host: "prod"}, opsconfig.Health{Type: "http", URL: raw, SuccessStatuses: []int{200}}, time.Second)
		if got.Err == nil || len(ex.requests) != 0 {
			t.Fatalf("url=%q result=%+v requests=%+v", raw, got, ex.requests)
		}
	}
	for _, timeout := range []time.Duration{1500 * time.Millisecond, 500 * time.Millisecond} {
		ex := &fakeExecutor{result: opsexec.Result{ExitCode: 0, Stdout: "200"}}
		got := Probe(context.Background(), ex, opsconfig.Environment{Kind: opsconfig.EnvironmentKindSSH, Host: "prod"}, opsconfig.Health{Type: "http", URL: "https://example.com/health", SuccessStatuses: []int{200}}, timeout)
		if !got.Healthy {
			t.Fatalf("timeout=%v result=%+v", timeout, got)
		}
		args := ex.requests[0].Args
		if args[len(args)-2] != "--" || args[len(args)-1] != "https://example.com/health" {
			t.Fatalf("args=%v", args)
		}
		want := map[time.Duration]string{1500 * time.Millisecond: "1.5", 500 * time.Millisecond: "0.5"}[timeout]
		if args[len(args)-3] != want {
			t.Fatalf("timeout=%v args=%v", timeout, args)
		}
	}
}

func TestHealthRemoteTCPRejectsUnsafeTargetAndRoundsTimeoutUp(t *testing.T) {
	for _, target := range []string{"-host:80", "host:-1", "host:0", "host:65536", "host:http", "missing-port"} {
		ex := &fakeExecutor{}
		got := Probe(context.Background(), ex, opsconfig.Environment{Kind: opsconfig.EnvironmentKindSSH, Host: "prod"}, opsconfig.Health{Type: "tcp", Address: target}, time.Second)
		if got.Err == nil || len(ex.requests) != 0 {
			t.Fatalf("target=%q result=%+v requests=%+v", target, got, ex.requests)
		}
	}
	for _, timeout := range []time.Duration{1500 * time.Millisecond, 500 * time.Millisecond} {
		ex := &fakeExecutor{result: opsexec.Result{ExitCode: 0}}
		got := Probe(context.Background(), ex, opsconfig.Environment{Kind: opsconfig.EnvironmentKindSSH, Host: "prod"}, opsconfig.Health{Type: "tcp", Address: "127.0.0.1:80"}, timeout)
		if !got.Healthy || !reflect.DeepEqual(ex.requests[0].Args, []string{"-z", "-w", map[time.Duration]string{1500 * time.Millisecond: "2", 500 * time.Millisecond: "1"}[timeout], "127.0.0.1", "80"}) {
			t.Fatalf("timeout=%v result=%+v requests=%+v", timeout, got, ex.requests)
		}
	}
}

func TestHealthHTTPCancellationAndResponseBodyClose(t *testing.T) {
	body := &trackingBody{}
	client := roundTripFunc(func(*http.Request) (*http.Response, error) { return &http.Response{StatusCode: 200, Body: body}, nil })
	got := probeHTTP(context.Background(), nil, opsconfig.Environment{Kind: opsconfig.EnvironmentKindLocal}, opsconfig.Health{Type: "http", URL: "http://example.com", SuccessStatuses: []int{200}}, time.Second, client)
	if !got.Healthy || !body.closed {
		t.Fatalf("result=%+v closed=%v", got, body.closed)
	}
	cancelClient := roundTripFunc(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	got = probeHTTP(ctx, nil, opsconfig.Environment{Kind: opsconfig.EnvironmentKindLocal}, opsconfig.Health{Type: "http", URL: "http://example.com", SuccessStatuses: []int{200}}, 10*time.Millisecond, cancelClient)
	if !got.TimedOut || !errors.Is(got.Err, context.DeadlineExceeded) {
		t.Fatalf("result=%+v", got)
	}
}

func TestHealthProbeDetailsNeverEchoExecutorPayload(t *testing.T) {
	secret := "credential-payload"
	for _, tt := range []struct {
		name    string
		env     opsconfig.Environment
		health  opsconfig.Health
		results []opsexec.Result
	}{{"process", opsconfig.Environment{PIDFile: "/tmp/demo.pid"}, opsconfig.Health{Type: "process"}, []opsexec.Result{{ExitCode: 0, Stdout: "42"}, {ExitCode: 0, Stdout: secret}}}, {"tcp", opsconfig.Environment{Kind: opsconfig.EnvironmentKindSSH, Host: "prod"}, opsconfig.Health{Type: "tcp", Address: "127.0.0.1:80"}, []opsexec.Result{{ExitCode: 0, Stdout: secret}}}} {
		t.Run(tt.name, func(t *testing.T) {
			ex := &sequenceExecutor{results: tt.results}
			got := Probe(context.Background(), ex, tt.env, tt.health, time.Second)
			if !got.Healthy || strings.Contains(got.Detail, secret) {
				t.Fatalf("result=%+v", got)
			}
		})
	}
}

func TestHealthLocalHTTPRejectsUnsafeURLs(t *testing.T) {
	for _, raw := range []string{"ftp://example.com/health", "http://user:secret@example.com/health", "/relative"} {
		got := Probe(context.Background(), nil, opsconfig.Environment{Kind: opsconfig.EnvironmentKindLocal}, opsconfig.Health{Type: "http", URL: raw, SuccessStatuses: []int{200}}, time.Second)
		if got.Err == nil {
			t.Fatalf("url=%q result=%+v", raw, got)
		}
	}
}

func TestHealthFailureDetailsNeverExposeUnderlyingErrorsOrStderr(t *testing.T) {
	secret := "token=top-secret"
	client := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("request failed for https://example.com/health?" + secret)
	})
	got := probeHTTP(context.Background(), nil, opsconfig.Environment{Kind: opsconfig.EnvironmentKindLocal}, opsconfig.Health{Type: "http", URL: "https://example.com/health?token=configured", SuccessStatuses: []int{200}}, time.Second, client)
	if got.Err == nil || got.Detail != "http probe failed" || strings.Contains(got.Detail, "token") {
		t.Fatalf("result=%+v", got)
	}
	for _, kind := range []string{"tcp", "process", "command"} {
		result := fromExec(kind, opsexec.Result{ExitCode: 7, Stderr: secret, Err: errors.New(secret)})
		if strings.Contains(result.Detail, secret) || result.Detail == "" {
			t.Fatalf("kind=%s result=%+v", kind, result)
		}
	}
}

type sequenceExecutor struct{ results []opsexec.Result }

func (e *sequenceExecutor) Run(context.Context, opsexec.Request) opsexec.Result {
	r := e.results[0]
	e.results = e.results[1:]
	return r
}
func (e *sequenceExecutor) Copy(context.Context, opsexec.CopyRequest) opsexec.Result {
	return opsexec.Result{}
}

type trackingBody struct{ closed bool }

func (b *trackingBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b *trackingBody) Close() error             { b.closed = true; return nil }

func TestHealthTCPClosesConnection(t *testing.T) {
	conn := &trackingConn{}
	got := probeTCP(context.Background(), nil, opsconfig.Environment{Kind: opsconfig.EnvironmentKindLocal}, opsconfig.Health{Type: "tcp", Address: "127.0.0.1:1"}, time.Second, fakeDialer{conn: conn})
	if !got.Healthy {
		t.Fatalf("result=%+v", got)
	}
	if !conn.closed {
		t.Fatal("probe connection remained open")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

type fakeDialer struct{ conn net.Conn }

func (d fakeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}

type trackingConn struct{ closed bool }

func (c *trackingConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *trackingConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *trackingConn) Close() error                     { c.closed = true; return nil }
func (c *trackingConn) LocalAddr() net.Addr              { return fakeAddr("local") }
func (c *trackingConn) RemoteAddr() net.Addr             { return fakeAddr("remote") }
func (c *trackingConn) SetDeadline(time.Time) error      { return nil }
func (c *trackingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *trackingConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }
