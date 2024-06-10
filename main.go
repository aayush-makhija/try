package invidns

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// Provider wraps the provider implementation as a Caddy module.
type Provider struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func init() {
	caddy.RegisterModule(Provider{})
}

// CaddyModule returns the Caddy module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.invidns",
		New: func() caddy.Module { return new(Provider) },
	}
}

// Provision sets up the provider by resolving placeholders and sending the request.
// Implements caddy.Provisioner.
func (p *Provider) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	p.URL = repl.ReplaceAll(p.URL, "")
	p.Username = repl.ReplaceAll(p.Username, "")
	p.Password = repl.ReplaceAll(p.Password, "")
	return p.SendRequest()
}

// SendRequest sends a request to the specified URL with the provider's details.
func (p *Provider) SendRequest() error {
	payload := map[string]string{
		"username":  p.Username,
		"password":  base64.StdEncoding.EncodeToString([]byte(p.Password)),
		"timestamp": time.Now().In(time.FixedZone("IST", 5.5*3600)).Format(time.RFC3339), // Indian Standard Time
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	req, err := http.NewRequest("POST", p.URL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-200 response: %v", resp.Status)
	}

	return nil
}

// UnmarshalCaddyfile sets up the DNS provider from Caddyfile tokens. Syntax:
//
//	requestbin {
//	    url <requestbin_url>
//	    username <username>
//	    password <password>
//	}
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "url":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.URL = d.Val() // Assign URL argument
			case "username":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.Username = d.Val() // Assign username argument
			case "password":
				if !d.NextArg() {
					return d.ArgErr()
				}
				p.Password = d.Val() // Assign password argument
			default:
				return d.Errf("random subdirective '%s'", d.Val())
			}
		}
	}
	return nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*Provider)(nil)
	_ caddy.Provisioner     = (*Provider)(nil)
)
