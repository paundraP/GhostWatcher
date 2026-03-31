package threatintel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var ErrNotConfigured = errors.New("virustotal api key not configured")

type LookupResult struct {
	Hash       string
	Malicious  bool
	ThreatName string
	Source     string
	Detail     string
}

type LookupClient interface {
	LookupHash(ctx context.Context, hash string) (LookupResult, error)
}

type VirusTotalClient struct {
	apiKey  string
	baseURL string
	client  *http.Client
}

func NewVirusTotalClient(apiKey string) *VirusTotalClient {
	return &VirusTotalClient{
		apiKey:  strings.TrimSpace(apiKey),
		baseURL: "https://www.virustotal.com/api/v3",
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (v *VirusTotalClient) Enabled() bool {
	return strings.TrimSpace(v.apiKey) != ""
}

func (v *VirusTotalClient) LookupHash(ctx context.Context, hash string) (LookupResult, error) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	if hash == "" {
		return LookupResult{}, fmt.Errorf("empty hash")
	}
	if !v.Enabled() {
		return LookupResult{}, ErrNotConfigured
	}

	endpoint := strings.TrimRight(v.baseURL, "/") + "/files/" + url.PathEscape(hash)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return LookupResult{}, err
	}
	req.Header.Set("x-apikey", v.apiKey)
	req.Header.Set("accept", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return LookupResult{}, err
	}
	defer resp.Body.Close()

	var payload vtFileResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return LookupResult{}, fmt.Errorf("decode virustotal response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		stats := payload.Data.Attributes.LastAnalysisStats
		malicious := stats.Malicious > 0 || stats.Suspicious > 0
		threatName := strings.TrimSpace(payload.Data.Attributes.PopularThreatClassification.SuggestedThreatLabel)
		if threatName == "" {
			if malicious {
				threatName = "suspicious_or_malicious"
			} else {
				threatName = ""
			}
		}
		detail := fmt.Sprintf("VT stats: malicious=%d suspicious=%d harmless=%d undetected=%d", stats.Malicious, stats.Suspicious, stats.Harmless, stats.Undetected)

		return LookupResult{
			Hash:       hash,
			Malicious:  malicious,
			ThreatName: threatName,
			Source:     "virustotal_api",
			Detail:     detail,
		}, nil
	case http.StatusNotFound:
		return LookupResult{
			Hash:      hash,
			Malicious: false,
			Source:    "virustotal_api",
			Detail:    "hash not found in VirusTotal",
		}, nil
	case http.StatusTooManyRequests:
		return LookupResult{}, fmt.Errorf("virustotal rate limit exceeded")
	case http.StatusUnauthorized, http.StatusForbidden:
		msg := payload.Error.Message
		if msg == "" {
			msg = "unauthorized"
		}
		return LookupResult{}, fmt.Errorf("virustotal auth error: %s", msg)
	default:
		msg := payload.Error.Message
		if msg == "" {
			msg = resp.Status
		}
		return LookupResult{}, fmt.Errorf("virustotal API error: %s", msg)
	}
}

type vtFileResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`
			PopularThreatClassification struct {
				SuggestedThreatLabel string `json:"suggested_threat_label"`
			} `json:"popular_threat_classification"`
		} `json:"attributes"`
	} `json:"data"`
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}
