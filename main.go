package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

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

func printJwt(jwt []byte, out io.Writer) error {
	dots := bytes.Count(jwt, []byte{'.'})
	if dots != 2 {
		return fmt.Errorf("jwt must contain exactly 2 dots, but found %d", dots)
	}
	parts := bytes.Split(jwt, []byte{'.'})
	// 0 = header, 1 = payload, 2 = signature

	pjson := prettyjson.NewFormatter()

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
	}
	return nil
}
