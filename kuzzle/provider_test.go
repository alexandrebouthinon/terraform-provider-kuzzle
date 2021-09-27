package kuzzle

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"gopkg.in/h2non/gock.v1"
)

func Test_checkConnection(t *testing.T) {
	type args struct {
		endpoint string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		mock    Mock
	}{
		{
			name:    "Success",
			wantErr: false,
			mock: Mock{
				enabled:    true,
				statusCode: 200,
				url:        "http://kuzzle:7512",
				route:      "/",
				response:   json.RawMessage(`{"result": "ok"}`),
			},
			args: args{
				endpoint: "http://kuzzle:7512",
			},
		},
		{
			name:    "Not reachable",
			wantErr: true,
			mock: Mock{
				enabled: false,
			},
			args: args{
				endpoint: "http://kuzzle:7512",
			},
		},
		{
			name:    "Bad Gateway",
			wantErr: true,
			mock: Mock{
				enabled:    true,
				statusCode: 502,
				url:        "http://kuzzle:7512",
				route:      "/",
			},
			args: args{
				endpoint: "http://kuzzle:7512",
			},
		},
		{
			name:    "Not authorized",
			wantErr: false,
			mock: Mock{
				enabled:    true,
				statusCode: 403,
				url:        "http://kuzzle:7512",
				route:      "/",
				response:   json.RawMessage(`{"result": "Not Authorized"}`),
			},
			args: args{
				endpoint: "http://kuzzle:7512",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.mock.enabled {
				defer gock.Off()
				gock.
					New(tt.mock.url).
					Get(tt.mock.route).
					Reply(tt.mock.statusCode).
					JSON(tt.mock.response)
			}

			if err := checkConnection(tt.args.endpoint); (err != nil) != tt.wantErr {
				t.Errorf("checkConnection() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_checkToken(t *testing.T) {
	type args struct {
		endpoint string
		token    string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		mock    Mock
	}{
		{
			name:    "Success",
			wantErr: false,
			mock: Mock{
				enabled:    true,
				statusCode: 200,
				url:        "http://kuzzle:7512",
				route:      "/_checkToken",
				response:   json.RawMessage(`{"result": {"valid": true}}`),
			},
			args: args{
				endpoint: "http://kuzzle:7512",
			},
		},
		{
			name:    "Invalid token",
			wantErr: true,
			mock: Mock{
				enabled:    true,
				statusCode: 200,
				url:        "http://kuzzle:7512",
				route:      "/_checkToken",
				response:   json.RawMessage(`{"result": {"valid": false}}`),
			},
			args: args{
				endpoint: "http://kuzzle:7512",
			},
		},
		{
			name:    "Not authorized",
			wantErr: false,
			mock: Mock{
				enabled:    true,
				statusCode: 403,
				url:        "http://kuzzle:7512",
				route:      "/_checkToken",
				response:   json.RawMessage(`{"result": "Not Authorized"}`),
			},
			args: args{
				endpoint: "http://kuzzle:7512",
			},
		},
		{
			name:    "Bad response format error",
			wantErr: true,
			mock: Mock{
				enabled:    true,
				statusCode: 200,
				url:        "http://kuzzle:7512",
				route:      "/_checkToken",
				response:   []byte("Not a JSON response"),
			},
			args: args{
				endpoint: "http://kuzzle:7512",
			},
		},
		{
			name:    "Connection error",
			wantErr: true,
			mock: Mock{
				enabled: false,
			},
			args: args{
				endpoint: "http://kuzzle:7512",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.mock.enabled {
				defer gock.Off()
				gock.
					New(tt.mock.url).
					Post(tt.mock.route).
					Reply(tt.mock.statusCode).
					JSON(tt.mock.response)
			}
			if err := checkToken(tt.args.endpoint, tt.args.token); (err != nil) != tt.wantErr {
				t.Errorf("checkToken() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_tryAuthenticate(t *testing.T) {
	type args struct {
		endpoint string
		username string
		password string
	}
	tests := []struct {
		name    string
		args    args
		wantJwt string
		wantErr bool
		mock    Mock
	}{
		{
			name:    "Success",
			wantErr: false,
			wantJwt: "mySuperAuthenticationToken",
			mock: Mock{
				enabled:    true,
				statusCode: 200,
				url:        "http://kuzzle:7512",
				route:      "/_login/local",
				response:   json.RawMessage(`{"result": {"jwt": "mySuperAuthenticationToken"}}`),
			},
			args: args{
				endpoint: "http://kuzzle:7512",
			},
		},
		{
			name:    "Bad credentials/Unauthorized error",
			wantErr: true,
			wantJwt: "",
			mock: Mock{
				enabled:    true,
				statusCode: 401,
				url:        "http://kuzzle:7512",
				route:      "/_login/local",
			},
			args: args{
				endpoint: "http://kuzzle:7512",
			},
		},
		{
			name:    "Bad response format error",
			wantErr: true,
			wantJwt: "",
			mock: Mock{
				enabled:    true,
				statusCode: 200,
				url:        "http://kuzzle:7512",
				route:      "/_login/local",
				response:   []byte("Not a JSON response"),
			},
			args: args{
				endpoint: "http://kuzzle:7512",
			},
		},
		{
			name:    "Connection error",
			wantErr: true,
			wantJwt: "",
			mock: Mock{
				enabled: false,
			},
			args: args{
				endpoint: "http://kuzzle:7512",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.mock.enabled {
				defer gock.Off()
				gock.
					New(tt.mock.url).
					Post(tt.mock.route).
					Reply(tt.mock.statusCode).
					JSON(tt.mock.response)
			}

			gotJwt, err := tryAuthenticate(tt.args.endpoint, tt.args.username, tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("tryAuthenticate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotJwt != tt.wantJwt {
				t.Errorf("tryAuthenticate() = %v, want %v", gotJwt, tt.wantJwt)
			}
		})
	}
}

func Test_providerConfigure(t *testing.T) {
	type args struct {
		ctx context.Context
		d   *schema.ResourceData
	}
	tests := []struct {
		name       string
		args       args
		wantConfig interface{}
		wantDiags  diag.Diagnostics
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotConfig, gotDiags := providerConfigure(tt.args.ctx, tt.args.d)
			if !reflect.DeepEqual(gotConfig, tt.wantConfig) {
				t.Errorf("providerConfigure() gotConfig = %v, want %v", gotConfig, tt.wantConfig)
			}
			if !reflect.DeepEqual(gotDiags, tt.wantDiags) {
				t.Errorf("providerConfigure() gotDiags = %v, want %v", gotDiags, tt.wantDiags)
			}
		})
	}
}
