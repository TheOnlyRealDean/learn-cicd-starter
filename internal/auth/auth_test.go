package auth

import (
    "net/http"
    "testing"
)

func TestGetAPIKey(t *testing.T) {
    tests := []struct {
        name       string
        headers    http.Header
        wantAPIKey string
        wantErr    error   // für ErrNoAuthHeaderIncluded
        wantErrMsg string  // für Fehler per Textvergleich
    }{
        {
            name: "no authorization header",
            headers: http.Header{},
            wantAPIKey: "",
            wantErr:    ErrNoAuthHeaderIncluded,
        },
        {
            name: "malformed header - wrong scheme",
            headers: http.Header{
                "Authorization": []string{"Bearer sometoken"},
            },
            wantAPIKey: "",
            wantErrMsg: "malformed authorization header",
        },
        {
            name: "malformed header - missing key",
            headers: http.Header{
                "Authorization": []string{"ApiKey"},
            },
            wantAPIKey: "",
            wantErrMsg: "malformed authorization header",
        },
        {
            name: "valid header",
            headers: http.Header{
                "Authorization": []string{"ApiKey supersecret"},
            },
            wantAPIKey: "supersecret",
            wantErr:    nil,
        },
    }

    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            gotKey, err := GetAPIKey(tc.headers)

            // Fehler prüfen
            if tc.wantErr != nil || tc.wantErrMsg != "" {
                if err == nil {
                    t.Fatalf("expected an error but got nil")
                }
                if tc.wantErr != nil && err != tc.wantErr {
                    t.Fatalf("expected error %v, got %v", tc.wantErr, err)
                }
                if tc.wantErrMsg != "" && err.Error() != tc.wantErrMsg {
                    t.Fatalf("expected error message %q, got %q", tc.wantErrMsg, err.Error())
                }
            } else {
                if err != nil {
                    t.Fatalf("expected no error, got %v", err)
                }
            }

            // API-Key prüfen
            if gotKey != tc.wantAPIKey {
                t.Fatalf("expected api key %q, got %q", tc.wantAPIKey, gotKey)
            }
        })
    }
}
