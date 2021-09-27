package kuzzle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type Config struct {
	Endpoint string // Kuzzle endpoint URL
	Token    string // API key or JWT
}

func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"endpoint": { // Kuzzle endpoint URL
				Type:        schema.TypeString,
				Required:    true,
				Description: "Kuzzle endpoint URL",
				DefaultFunc: schema.EnvDefaultFunc("KUZZLE_ENDPOINT", nil),
				ValidateFunc: func(v interface{}, k string) (ws []string, errors []error) {
					if v.(string) == "" {
						errors = append(errors, fmt.Errorf("%q must be a non-empty string", k))
					}

					URL, err := url.Parse(v.(string))
					if err != nil {
						errors = append(errors, fmt.Errorf("%q must be a valid URL", k))
					}

					if URL.Scheme != "http" && URL.Scheme != "https" {
						errors = append(errors, fmt.Errorf("%q must be a valid URL with http or https scheme", k))
					}

					return
				},
			},
			"api_key": { // API key or JWT
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Kuzzle API key",
				DefaultFunc: schema.EnvDefaultFunc("KUZZLE_API_KEY", nil),
			},
			"username": { // Username
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("KUZZLE_USERNAME", nil),
				Description: "Kuzzle username",
			},
			"password": { // Password
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("KUZZLE_PASSWORD", nil),
				Description: "Kuzzle password",
			},
		},

		ResourcesMap: map[string]*schema.Resource{},

		ConfigureContextFunc: providerConfigure,
	}
}

// providerConfigure is called to configure the provider.
// It tests the connection to the Kuzzle server and tries to authenticate with the provided credentials
func providerConfigure(
	ctx context.Context,
	d *schema.ResourceData,
) (config interface{}, diags diag.Diagnostics) {
	endpoint := d.Get("endpoint").(string)
	apiKey := d.Get("api_key").(string)
	username := d.Get("username").(string)
	password := d.Get("password").(string)

	err := checkConnection(endpoint)
	if err != nil {
		return nil, diag.Errorf("Error connecting to Kuzzle: %s", err)
	}

	// If we have username/password, try to authenticate
	if username != "" && password != "" {
		jwt, err := tryAuthenticate(endpoint, username, password)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Kuzzle authentication failed",
				Detail:   err.Error(),
			})
			return
		}

		config = &Config{
			Endpoint: endpoint,
			Token:    jwt,
		}
	}

	// If no username/password pair is provided, we try to check the API key validity
	if apiKey != "" {
		err := checkToken(endpoint, apiKey)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Kuzzle provided API key is invalid",
				Detail:   err.Error(),
			})
			return
		}

		config = &Config{
			Endpoint: endpoint,
			Token:    apiKey,
		}
	}

	// If no authentication method is provided, we try to use anonymous authentication
	if config == nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "Kuzzle authentication credentials not provided",
			Detail:   "No authentication credentials provided. Using anonymous authentication...",
		})

		config = &Config{
			Endpoint: endpoint,
		}
	}

	return
}

// checkConnection tests the connection to the Kuzzle server
func checkConnection(endpoint string) error {
	client := &http.Client{}
	resp, err := client.Get(endpoint)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusServiceUnavailable {
		return fmt.Errorf("Kuzzle server is not reachable")
	}

	return nil
}

// checkToken tests the validity of the provided API key
func checkToken(endpoint string, token string) error {
	httpClient := &http.Client{}
	reqBody, _ := json.Marshal(map[string]string{
		"jwt": token,
	})

	resp, err := httpClient.Post(endpoint+"/_checkToken", "application/json", ioutil.NopCloser(bytes.NewReader(reqBody)))
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return err
	}

	defer resp.Body.Close()
	var jsonBody map[string]interface{}
	body, _ := ioutil.ReadAll(resp.Body)

	if err := json.Unmarshal(body, &jsonBody); err != nil {
		return err
	}

	if jsonBody["result"].(map[string]interface{})["valid"].(bool) != true {
		return fmt.Errorf("Kuzzle API key is invalid")
	}

	return nil
}

// tryAuthenticate tries to authenticate with the provided username/password using local strategy
func tryAuthenticate(endpoint string, username string, password string) (jwt string, err error) {
	httpClient := &http.Client{}
	reqBody, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})

	resp, err := httpClient.Post(endpoint+"/_login/local", "application/json", ioutil.NopCloser(bytes.NewReader(reqBody)))
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Kuzzle authentication failed")
	}

	defer resp.Body.Close()
	var jsonBody map[string]interface{}
	body, _ := ioutil.ReadAll(resp.Body)

	if err := json.Unmarshal(body, &jsonBody); err != nil {
		return "", err
	}

	return jsonBody["result"].(map[string]interface{})["jwt"].(string), nil
}
