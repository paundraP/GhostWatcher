package server

import (
	"context"
	"testing"

	ghostwatcherv1 "ghostwatcher/internal/gen/ghostwatcherv1"
	"ghostwatcher/internal/threatintel"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAuthorizeErrors(t *testing.T) {
	svc := NewService(NewNoopStore(), nil)
	resp, err := svc.EnrollMac(context.Background(), &ghostwatcherv1.EnrollMacRequest{
		Hostname:          "team-mac",
		OsVersion:         "14.0",
		SerialNumber:      "C02TEST12345",
		GatekeeperEnabled: true,
		SipEnabled:        true,
	})
	if err != nil {
		t.Fatalf("EnrollMac failed: %v", err)
	}

	if _, err := svc.authorize(resp.GetAgentId(), "wrong-token"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}

	if _, err := svc.authorize("unknown-agent", "anything"); status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound, got %v", err)
	}
}

func TestLookupHash(t *testing.T) {
	svc := NewService(NewNoopStore(), nil)

	malicious, err := svc.LookupHash(context.Background(), &ghostwatcherv1.XProtectLookupRequest{Hash: threatintel.ShlayerHash})
	if err != nil {
		t.Fatalf("LookupHash malicious failed: %v", err)
	}
	if malicious.GetVerdict() != ghostwatcherv1.XProtectLookupResponse_MALICIOUS {
		t.Fatalf("expected MALICIOUS verdict, got %s", malicious.GetVerdict().String())
	}

	safe, err := svc.LookupHash(context.Background(), &ghostwatcherv1.XProtectLookupRequest{Hash: "aaaaaaaa"})
	if err != nil {
		t.Fatalf("LookupHash safe failed: %v", err)
	}
	if safe.GetVerdict() != ghostwatcherv1.XProtectLookupResponse_SAFE {
		t.Fatalf("expected SAFE verdict, got %s", safe.GetVerdict().String())
	}
}

func TestPostureScore(t *testing.T) {
	if got := postureScore(false, false); got != 40 {
		t.Fatalf("expected 40, got %d", got)
	}
	if got := postureScore(true, false); got != 70 {
		t.Fatalf("expected 70, got %d", got)
	}
	if got := postureScore(true, true); got != 100 {
		t.Fatalf("expected 100, got %d", got)
	}
}
