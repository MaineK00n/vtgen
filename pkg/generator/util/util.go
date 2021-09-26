package util

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path"
	"time"

	vulsmodels "github.com/future-architect/vuls/models"
)

func RandomSample(s []string, num int) []string {
	rand.Seed(time.Now().UnixNano())
	var sample []string
	n := make([]string, len(s))
	copy(n, s)

	for i := 0; i < num; i++ {
		index := rand.Intn(len(n))
		sample = append(sample, n[index])
		n = append(n[:index], n[index+1:]...)
	}
	return sample
}

func RandomChoice(m map[string][]string) string {
	index := rand.Intn(len(m))
	i := 0

	ans := ""
	for k := range m {
		if index == i {
			ans = k
			break
		} else {
			i++
		}
	}
	return ans
}

// IndexChunk has a starting point and an ending point for Chunk
type IndexChunk struct {
	From, To int
}

func ChunkSlice(length int, chunkSize int) <-chan IndexChunk {
	ch := make(chan IndexChunk)

	go func() {
		defer close(ch)

		for i := 0; i < length; i += chunkSize {
			idx := IndexChunk{i, i + chunkSize}
			if length < idx.To {
				idx.To = length
			}
			ch <- idx
		}
	}()

	return ch
}

func OutputResult(result vulsmodels.ScanResult, dirPath string) error {
	json, err := json.MarshalIndent(result, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal json: %w", err)
	}

	fp, err := os.Create(path.Join(dirPath, fmt.Sprintf("%s.json", result.ServerName)))
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer fp.Close()
	fp.WriteString(string(json))
	return nil
}
