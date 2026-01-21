package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/hashicorp/cap/jwt"
	"github.com/hokaccha/go-prettyjson"
	"github.com/mattn/go-isatty"
	"github.com/urfave/cli/v3"
)

// version is set at build time via -ldflags
var version = "dev"

type jwtTimes struct {
	iat *time.Time
	nbf *time.Time
	exp *time.Time
}

type jwtOpts struct {
	verifySig   bool
	httpTimeout time.Duration
}

func main() {
	cmd := &cli.Command{
		Name:    "jwt",
		Usage:   "Simple JWT inspection tool",
		Version: version,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "verify-signature",
				Aliases: []string{"sig"},
				Usage:   "Validate the JWT signature using the issuer's JWKs",
				Sources: cli.EnvVars("VALIDATE_SIGNATURE"),
			},
			&cli.DurationFlag{
				Name:    "http-timeout",
				Usage:   "Timeout for HTTP requests when fetching JWKs",
				Value:   5 * time.Second,
				Sources: cli.EnvVars("HTTP_TIMEOUT"),
			},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			verifySig := c.Bool("verify-signature")
			httpTimeout := c.Duration("http-timeout")

			tokens := c.Args().Slice()
			// read tokens from stdin if no args are provided
			if len(tokens) == 0 {
				buf := bytes.Buffer{}
				if _, err := io.Copy(&buf, os.Stdin); err != nil {
					return fmt.Errorf("could not read from stdin: %w\n", err)
				}
				token := strings.TrimSpace(buf.String())
				if token == "" {
					return fmt.Errorf("no JWT token provided via arguments or stdin")
				}
				tokens = append(tokens, token)
			}

			// disable color if output is not a terminal
			color.NoColor = !isatty.IsTerminal(os.Stdout.Fd())

			opts := jwtOpts{
				verifySig:   verifySig,
				httpTimeout: httpTimeout,
			}

			errs := []error{}
			for _, t := range tokens {
				if err := printJwt(ctx, t, os.Stdout, opts); err != nil {
					errs = append(errs, err)
					fmt.Fprintf(os.Stderr, "could not parse JWT: %v\n", err)
				}
			}

			return errors.Join(errs...)
		},
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := cmd.Run(ctx, os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func printJwt(ctx context.Context, token string, out io.Writer, opts jwtOpts) error {
	token = strings.TrimSpace(token)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("jwt must contain exactly 3 parts, but found %d", len(parts))
	}
	// 0 = header, 1 = payload, 2 = signature
	partTypes := []string{"header", "payload", "signature"}

	pjson := prettyjson.NewFormatter()

	iss := ""
	times := jwtTimes{}
	for i := range parts[0:2] {
		part := parts[i]
		partType := partTypes[i]

		dec, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return fmt.Errorf("failed to base64-decode %s: %w", partType, err)
		}

		obj := map[string]any{}
		err = json.Unmarshal(dec, &obj)
		if err != nil {
			return fmt.Errorf("failed to parse json of %s: %w", partType, err)
		}
		s, err := pjson.Marshal(obj)
		if err != nil {
			return err
		}
		if _, err := out.Write(s); err != nil {
			return err
		}
		if _, err := out.Write([]byte{'\n'}); err != nil {
			return err
		}
		if partType == "payload" {
			iss, _ = obj["iss"].(string)
			for _, e := range []string{"iat", "nbf", "exp"} {
				v, set := obj[e]
				if !set {
					continue
				}
				f, ok := v.(float64)
				if !ok {
					return fmt.Errorf("expected %s to be a number, got %T", e, v)
				}
				t := time.Unix(int64(f), 0)
				switch e {
				case "iat":
					times.iat = &t
				case "nbf":
					times.nbf = &t
				case "exp":
					times.exp = &t
				}
			}
		}
	}

	colorOk := color.New(color.FgGreen).SprintFunc()
	colorNok := color.New(color.FgRed).SprintFunc()

	now := time.Now()
	if times.iat != nil {
		diff := times.iat.Sub(now).Truncate(time.Second)
		diffWord := "left"
		if diff < 0 {
			diffWord = "ago"
		}
		relTime := fmt.Sprint(diff.Abs(), " ", diffWord)
		fmt.Fprintf(out, "// iat: %v | %s\n", times.iat, relTime)
	}

	if times.nbf != nil {
		diff := times.nbf.Sub(now).Truncate(time.Second)
		colorFn := colorOk
		diffWord := "ago"
		if diff >= 0 {
			diffWord = "left"
			colorFn = colorNok
		}
		relTime := colorFn(diff.Abs(), " ", diffWord)
		fmt.Fprintf(out, "// nbf: %v | %s\n", times.nbf, relTime)
	}

	if times.exp != nil {
		diff := times.exp.Sub(now).Truncate(time.Second)
		diffWord := "left"
		colorFn := colorOk
		if diff < 0 {
			diffWord = "ago"
			colorFn = colorNok
		}
		relTime := colorFn(diff.Abs(), " ", diffWord)
		fmt.Fprintf(out, "// exp: %v | %s\n", times.exp, relTime)
	}

	if opts.verifySig {
		err := validateJWTSignature(ctx, token, iss, opts.httpTimeout)
		sigResult := colorOk("VALID")
		if err != nil {
			sigResult = colorNok("INVALID (", err, ")")
		}
		fmt.Fprintf(out, "// signature: %s\n", sigResult)
	}
	return nil
}

func validateJWTSignature(ctx context.Context, token, issuer string, httpTimeout time.Duration) error {
	if issuer == "" {
		return fmt.Errorf("issuer is empty")
	}

	// Fetch OpenID configuration from well-known URL
	issURL, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("invalid issuer URL: %w", err)
	}

	wellKnownURL := issURL.JoinPath(".well-known", "openid-configuration").String()
	jwksURI, err := fetchJWKsURI(ctx, wellKnownURL, httpTimeout)
	if err != nil {
		return fmt.Errorf("failed to fetch OpenID configuration: %w", err)
	}

	keySet, err := jwt.NewJSONWebKeySet(ctx, jwksURI, "")
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	if _, err := keySet.VerifySignature(ctx, token); err != nil {
		return err
	}

	return nil
}

func fetchJWKsURI(ctx context.Context, wellKnownURL string, httpTimeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	config := struct {
		JWKsURI string `json:"jwks_uri"`
	}{}

	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return "", err
	}

	if config.JWKsURI == "" {
		return "", fmt.Errorf("jwks_uri not found in OpenID configuration")
	}

	return config.JWKsURI, nil
}
