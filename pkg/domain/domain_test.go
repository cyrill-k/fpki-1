package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIsValidDomain: test strange domain names
func TestIsValidDomain(t *testing.T) {
	parser, err := NewDomainParser()
	require.NoError(t, err)

	tests := map[string]bool{
		".com":                        false,
		"com":                         false,
		"net":                         false,
		".baidu.com":                  false,
		"423525.baidu.com":            false,
		"_www.baidu.com":              false,
		"*.*.baidu.com":               false,
		"device-a6789012.baidu.com":   true,
		"www.baidu.com":               true,
		"www.google.com":              true,
		"bqiwodnqwpdq.www.google.com": true,
	}

	for k, v := range tests {
		assert.Equal(t, v, parser.IsValidDomain(k))
	}
}

func TestUniqueValidDomainName(t *testing.T) {
	parser, err := NewDomainParser()
	require.NoError(t, err)

	test := map[string]struct {
		input  []string
		length int
	}{
		"1": {
			input:  []string{"www.baidu.com", "www.baidu.com"},
			length: 1,
		},
		"2": {
			input:  []string{"*.baidu.com", "www.baidu.com", "baidu.com"},
			length: 1,
		},
		"3": {
			input:  []string{"com", "*.*.baidu.com", "12378.com"},
			length: 0,
		},
		"4": {
			input:  []string{"video.google.com", "mail.google.com", "audio.google.com"},
			length: 3,
		},
	}

	for _, v := range test {
		assert.Equal(t, v.length, len(parser.uniqueValidDomainName(v.input)))
	}
}

func TestSplitE2LD(t *testing.T) {
	test := map[string]struct {
		input  string
		output []string
		length int
	}{
		"1": {
			input:  "baidu.com",
			output: []string{"baidu.com"},
			length: 1,
		},

		"2": {
			input:  "video.www.baidu.com",
			output: []string{"baidu.com", "www", "video"},
			length: 3,
		},

		"3": {
			input:  "video.baidu.com",
			output: []string{"baidu.com", "video"},
			length: 2,
		},
	}

	for _, v := range test {
		result, err := SplitE2LD(v.input)
		assert.NoError(t, err)
		assert.Equal(t, v.length, len(result))
		for _, outputString := range v.output {
			assert.Contains(t, result, outputString)
		}
	}
}

func TestFindLongestSuffix(t *testing.T) {
	test := map[string]struct {
		input  [][]string
		output string
	}{
		"1": {
			input:  [][]string{{"mail", "video"}, {"audio", "video"}},
			output: "video.",
		},
		"2": {
			input:  [][]string{{"tv", "mail", "video"}, {"mail", "video"}, {"mail", "video"}},
			output: "mail.video.",
		},
		"3": {
			input:  [][]string{{"tv", "mail", "mail"}, {"mail", "mail"}, {"mail", "video"}},
			output: "",
		},
	}

	for _, v := range test {
		assert.Equal(t, v.output, findLongestSuffix(v.input))
	}

}

func TestExtractAffectedDomains(t *testing.T) {
	parser, err := NewDomainParser()
	require.NoError(t, err)

	test := map[string]struct {
		input  []string
		output []string
	}{
		"1": {
			input:  []string{"www.baidu.com", "www.google.com"},
			output: []string{"baidu.com", "google.com"},
		},
		"2": {
			input:  []string{"www.baidu.com", "*.baidu.com"},
			output: []string{"baidu.com"},
		},
		"3": {
			input:  []string{"video.baidu.com", "*.baidu.com", "mail.baidu.com"},
			output: []string{"baidu.com", "video.baidu.com", "mail.baidu.com"},
		},
		"4": {
			input:  []string{"video.baidu.com", "*.baidu.com", "mail.baidu.com", "book.baidu.com", "func.baidu.com"},
			output: []string{"baidu.com"},
		},
		"5": {
			input: []string{"video.baidu.com", "*.baidu.com", "mail.baidu.com", "book.baidu.com",
				"func.baidu.com", "video.google.com", "mail.google.com", "book.mail.google.com"},
			output: []string{"baidu.com", "google.com"},
		},
	}

	for k, v := range test {
		result := parser.ExtractAffectedDomains(v.input)
		assert.Equal(t, len(v.output), len(result), k)
		for _, outputString := range v.output {
			assert.Contains(t, result, outputString)
		}
	}
}

func TestParseDomainName(t *testing.T) {
	parser, err := NewDomainParser()
	require.NoError(t, err)

	noErr := map[string]struct {
		input  string
		length int
		output []string
	}{
		"1": {
			input:  "www.baidu.com",
			length: 1,
			output: []string{"baidu.com"},
		},
		"2": {
			input:  "video.mail.baidu.com",
			length: 3,
			output: []string{"video.mail.baidu.com", "mail.baidu.com", "baidu.com"},
		},
	}

	hasErr := map[string]struct {
		input string
	}{
		"1": {
			input: "*.*.baidu.com",
		},
		"2": {
			input: "_hi.baidu.com",
		},
	}

	for _, v := range noErr {
		result, err := parser.ParseDomainName(v.input)
		require.NoError(t, err)
		assert.Equal(t, v.length, len(result))
		for _, outputString := range v.output {
			assert.Contains(t, result, outputString)
		}
	}

	for _, v := range hasErr {
		_, err = parser.ParseDomainName(v.input)
		require.Error(t, err)
	}
}
