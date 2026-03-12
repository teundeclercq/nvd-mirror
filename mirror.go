package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const nvdBase = "https://static.nvd.nist.gov/feeds/json/cve/2.0"
const kevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

var client = &http.Client{
	Timeout: 60 * time.Second,
}

func fetch(url string) ([]byte, error) {

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "nvd-mirror")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http %d %s", resp.StatusCode, url)
	}

	return io.ReadAll(resp.Body)
}

func readSHA(meta []byte) string {

	scanner := bufio.NewScanner(strings.NewReader(string(meta)))

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "sha256:") {
			return strings.TrimPrefix(line, "sha256:")
		}
	}

	return ""
}

func fileSHA(metaPath string) string {

	data, err := os.ReadFile(metaPath)
	if err != nil {
		return ""
	}

	return readSHA(data)
}

func ensureDir(p string) {
	os.MkdirAll(p, os.ModePerm)
}

func downloadFeed(file string, wg *sync.WaitGroup) {

	defer wg.Done()

	base := strings.TrimSuffix(file, ".json.gz")

	metaURL := nvdBase + "/" + base + ".meta"
	jsonURL := nvdBase + "/" + file

	// rename nvdcve-2.0-* -> nvdcve-*
	mirrorBase := strings.Replace(base, "nvdcve-2.0-", "nvdcve-", 1)

	metaPath := filepath.Join("nvd", mirrorBase+".meta")
	jsonPath := filepath.Join("nvd", mirrorBase+".json.gz")

	fmt.Println("Checking", file)

	metaData, err := fetch(metaURL)
	if err != nil {
		fmt.Println("meta error:", err)
		return
	}

	newSHA := readSHA(metaData)
	oldSHA := fileSHA(metaPath)

	if newSHA == oldSHA && oldSHA != "" {
		fmt.Println("unchanged", file)
		return
	}

	fmt.Println("downloading", file)

	data, err := fetch(jsonURL)
	if err != nil {
		fmt.Println("download error:", err)
		return
	}

	os.WriteFile(jsonPath, data, 0644)
	os.WriteFile(metaPath, metaData, 0644)
}

func downloadKEV() {

	fmt.Println("Checking CISA KEV")

	data, err := fetch(kevURL)
	if err != nil {
		fmt.Println("kev error:", err)
		return
	}

	path := "cisa/known_exploited_vulnerabilities.json"

	old, err := os.ReadFile(path)
	if err == nil && string(old) == string(data) {
		fmt.Println("kev unchanged")
		return
	}

	fmt.Println("updating kev")
	os.WriteFile(path, data, 0644)
}

func main() {

	ensureDir("nvd")
	ensureDir("cisa")

	currentYear := time.Now().Year()

	files := []string{
		"nvdcve-2.0-modified.json.gz",
		"nvdcve-2.0-recent.json.gz",
	}

	for y := 2002; y <= currentYear; y++ {
		files = append(files, fmt.Sprintf("nvdcve-2.0-%d.json.gz", y))
	}

	var wg sync.WaitGroup

	for _, f := range files {
		wg.Add(1)
		go downloadFeed(f, &wg)
	}

	wg.Wait()

	downloadKEV()

	fmt.Println("Mirror update complete")
}
