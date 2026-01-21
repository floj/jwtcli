package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/hokaccha/go-prettyjson"
)

func main() {
	tokens := [][]byte{}
	if len(os.Args) == 1 {
		jwt, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could read from stdin: %v", err)
			os.Exit(1)
		}
		tokens = append(tokens, jwt)
	} else {
		for _, t := range os.Args[1:] {
			tokens = append(tokens, []byte(t))
		}
	}

	for _, t := range tokens {
		if err := printJwt(t, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "could not parse JWT: %v", err)
			os.Exit(1)
		}
	}

}

type timeField struct {
	name  string
	value time.Time
}

func printJwt(jwt []byte, out io.Writer) error {
	dots := bytes.Count(jwt, []byte{'.'})
	if dots != 2 {
		return fmt.Errorf("jwt must contain exactly 2 dots, but found %d", dots)
	}
	parts := bytes.Split(jwt, []byte{'.'})
	// 0 = header, 1 = payload, 2 = signature

	pjson := prettyjson.NewFormatter()

	times := []timeField{}
	for partType, part := range map[string][]byte{"header": parts[0], "payload": parts[1]} {
		dec := make([]byte, len(part))
		n, err := base64.RawURLEncoding.Decode(dec, part)
		if err != nil {
			return fmt.Errorf("failed to base64-decode %s: %w", partType, err)
		}
		dec = dec[:n]
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
				times = append(times, timeField{name: e, value: t})
			}
		}
	}

	for _, tf := range times {
		timeDiff := ""
		now := time.Now()
		if tf.value.Before(now) {
			timeDiff = fmt.Sprintf("%s ago", now.Sub(tf.value).Truncate(time.Second).String())
		} else {
			timeDiff = fmt.Sprintf("%s left", tf.value.Sub(now).Truncate(time.Second))
		}
		fmt.Fprintf(out, "// %s: %v | %s\n", tf.name, tf.value, timeDiff)
	}
	return nil
}
