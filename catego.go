package main

import (
	"fmt"
	"flag"
	"strconv"
	"strings"
	"os"
	"bufio"
	"io"
	"regexp"
	"net/http"
	"io/ioutil"
	"encoding/json"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"net/url"
	"bytes"
	"unicode"
	"path/filepath"
)

type Entry struct {
	EntryId                  int64 `json:"id"`
	Title                    string `json:"title"`
	Contents                 string `json:"contents"`
	Format                   string `json:"format"`
	CategoryString           string `json:"categoryString"`
	Published                bool `json:"published"`
	Version                  int64 `json:"version"`
	UpdateLastModifiedDate   bool `json:"updateLastModifiedDate"`
	SaveInHistory            bool `json:"saveInHistory"`
}

type Page struct {
	TotalElements    int64 `json:"totalElements"`
	NumberOfElements int64 `json:"numberOfElements"`
	FirstPage        bool `json:"firstPage"`
	LastPage         bool `json:"lastPage"`
	TotalPages       int64 `json:"totalPages"`
	Size             int64 `json:"size"`
	Number           int64 `json:"number"`
}

type EntryPage struct {
	Page
	Content []Entry `json:"content"`
}

func (entry* Entry) Save(basedir string) bool {
	chk, err := os.Open(basedir)
	defer chk.Close()
	if err != nil {
		fmt.Println("create " + basedir)
		os.MkdirAll(basedir, 0777)
	}
	if (entry.EntryId < 1) {
		fmt.Println("cannot save")
		return false
	}

	filename := fmt.Sprintf("%s/%d.%s", basedir, entry.EntryId, entry.Format)
	f, _ := os.Create(filename)
	defer f.Close()
	f.WriteString("title: " + entry.Title + "\n")
	f.WriteString("category: " + entry.CategoryString + "\n")
	f.WriteString(fmt.Sprintf("published: %t\n", entry.Published))
	f.WriteString(fmt.Sprintf("updateLastModifiedDate: %t\n", entry.UpdateLastModifiedDate))
	f.WriteString(fmt.Sprintf("saveInHistory: %t\n", entry.SaveInHistory))
	f.WriteString("\n")
	f.WriteString("----\n")
	f.WriteString("\n")
	f.WriteString(entry.Contents)
	f.Sync()
	fmt.Println("wrote " + filename)
	return true
}

func (entry* Entry) NewReader() io.Reader {
	data, _ := json.Marshal(entry)
	return bytes.NewReader(data)
}

type Header struct {
	pattern *regexp.Regexp
	delim string
	data map[string] string
}

func (header *Header) ParseLine(line string) {
	vals := header.pattern.FindStringSubmatch(line)
	key := vals[1]
	value := vals[2]
	header.data[strings.ToUpper(key)] = value
}

func (header *Header) IsHeader(line string) bool {
	return header.pattern.MatchString(line)
}

func (header *Header) IsHeaderFinished(line string) bool {
	return strings.TrimSpace(line) == header.delim
}

func (header *Header) Get(key string) string {
	return header.data[strings.ToUpper(key)]
}

func (header *Header) Apply(entry *Entry) {
	entry.Title = header.Get("title")
	entry.CategoryString = header.Get("category")
	if header.Get("published") != "" {
		published, _ := strconv.ParseBool(header.Get("published"))
		entry.Published = published
	} else {
		entry.Published = false
	}
	if header.Get("updateLastModifiedDate") != "" {
		updateLastModifiedDate, _ := strconv.ParseBool(header.Get("updateLastModifiedDate"))
		entry.UpdateLastModifiedDate = updateLastModifiedDate
	} else {
		entry.UpdateLastModifiedDate = false
	}
	if header.Get("saveInHistory") != "" {
		saveInHistory, _ := strconv.ParseBool(header.Get("saveInHistory"))
		entry.SaveInHistory = saveInHistory
	} else {
		entry.SaveInHistory = false
	}
}

func getEntries(page int, accessToken string, endpoint string, basedir string) {
	fmt.Println("download page", page)
	var entryPage EntryPage
	getForEntity(fmt.Sprintf(endpoint+"/api/v1/entries/?page=%d", page), accessToken)(&entryPage)
	for _, entry := range entryPage.Content {
		entry.Save(basedir)
	}
}

func getEntry(filename string, accessToken string, endpoint string, basedir string) {
	entryId, _ := getEntryIdAndFormat(filename)

	fmt.Println("download ", entryId)
	var entry Entry
	getForEntity(endpoint+"/api/v1/entries/"+entryId, accessToken)(&entry)
	entry.Save(basedir)
}

func postEntry(filename string, accessToken string, endpoint string, basedir string) {
	_, format := getEntryIdAndFormat(filename)

	var entry Entry;
	entry.Format = format
	contents, header := readContents(filename)
	entry.Contents = strings.TrimLeftFunc(contents, unicode.IsSpace)
	header.Apply(&entry)

	var created Entry
	postForEntity(endpoint+"/api/v1/entries", entry, accessToken)(&created)

	if created.Save(basedir) {
		removeFile(filename)
	}
}

func putEntry(filename string, accessToken string, endpoint string, basedir string) {
	entryId, format := getEntryIdAndFormat(filename)

	var entry Entry
	var header *Header
	entry.EntryId, _ = strconv.ParseInt(entryId, 0, 32)
	entry.Format = format
	contents, header := readContents(filename)
	entry.Contents = strings.TrimLeftFunc(contents, unicode.IsSpace)
	header.Apply(&entry)

	var updated Entry
	putForEntity(endpoint+"/api/v1/entries/"+entryId, entry, accessToken)(&updated)
	updated.Save(basedir)
}


func deleteEntry(filename string, accessToken string, endpoint string) {
	entryId, _ := getEntryIdAndFormat(filename)
	deleteForEntity(endpoint+"/api/v1/entries/"+entryId, accessToken)(nil)
	removeFile(filename)
}

func getForEntity(url string, accessToken string) func(v interface{}) error {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("X-Admin", "true")

	if err != nil {
		panic(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	if (resp.StatusCode != 200) {
		ret := map[string] string {}
		json.Unmarshal(contents, &ret)
		return func(v interface{}) error {
			fmt.Println(resp.Status + " (" + ret["error_description"] + ")")
			return nil
		}
	}

	return func(v interface{}) error {
		return json.Unmarshal(contents, v)
	}
}

func postForEntity(url string, entry Entry, accessToken string) func(v interface{}) error {
	client := &http.Client{}
	req, err := http.NewRequest("POST", url, entry.NewReader())
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("X-Admin", "true")

	if err != nil {
		panic(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		panic(err)
	}
	if (resp.StatusCode != 201) {
		ret := map[string] string {}
		json.Unmarshal(contents, &ret)
		return func(v interface{}) error {
			fmt.Println(resp.Status + " (" + ret["error_description"] + ")")
			return nil
		}
	}

	return func(v interface{}) error {
		return json.Unmarshal(contents, v)
	}
}

func putForEntity(url string, entry Entry, accessToken string) func(v interface{}) error {
	client := &http.Client{}
	req, err := http.NewRequest("PUT", url, entry.NewReader())
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("X-Admin", "true")

	if err != nil {
		panic(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		panic(err)
	}
	if (resp.StatusCode != 200) {
		ret := map[string] string {}
		json.Unmarshal(contents, &ret)
		return func(v interface{}) error {
			fmt.Println(resp.Status + " (" + ret["error_description"] + ")")
			return nil
		}
	}

	return func(v interface{}) error {
		return json.Unmarshal(contents, v)
	}
}

func deleteForEntity(url string, accessToken string) func(v interface{}) error {
	client := &http.Client{}
	req, err := http.NewRequest("DELETE", url, nil)
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("X-Admin", "true")

	if err != nil {
		panic(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	if (resp.StatusCode != 204) {
		ret := map[string] string {}
		json.Unmarshal(contents, &ret)
		return func(v interface{}) error {
			fmt.Println(resp.Status + " (" + ret["error_description"] + ")")
			return nil
		}
	}

	return func(v interface{}) error {
		return nil
	}
}

func readContents(filename string) (string, *Header) {
	f, err := os.Open(filename)
	if err != nil {
		fmt.Println(filename + " is not found!")
		panic(err)
	}
	reader := bufio.NewReader(f)

	contents := ""
	var line string
	var isReadingHeader bool

	headerPattern, _ := regexp.Compile("(.+): (.+)")
	header := &Header {headerPattern, "----", make(map[string] string)}

	// check first line
	line, err = reader.ReadString('\n')
	isReadingHeader = header.IsHeader(line)

	if isReadingHeader {
		header.ParseLine(line)
	} else {
		contents += line
	}
	for {
		line, err = reader.ReadString('\n')

		if err == io.EOF {
			contents += line
			break;
		}

		if (isReadingHeader) {
			if header.IsHeader(line) {
				header.ParseLine(line)
			} else if header.IsHeaderFinished(line) {
				isReadingHeader = false
			}
			continue
		}

		contents += line
	}

	return contents, header
}


func getEntryIdAndFormat(filename string) (string, string) {
	basename := filepath.Base(filename)
	result := strings.Split(basename, ".")
	size := len(result)
	if size == 0 {
		panic("<filename> is not specified!")
	} else if size == 1 {
		return basename, "md"
	}
	entryId := strings.Join(result[:size-1], ".")
	format := result[size - 1:][0]
	return entryId, format
}

// encrypt string to base64 crypto using AES
func enceypt(key []byte, text string) string {
	plaintext := []byte(text)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// convert to base64
	return base64.URLEncoding.EncodeToString(ciphertext)
}

// decrypt from base64 to decrypted string
func deceypt(key []byte, cryptoText string) string {
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext)
}

const (
	MAGIC = "cafebabecafed00d"
)

func createNewKey(filename string) []byte {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("enter your secret key to encrypt: ")
	scanner.Scan()
	keyString := (scanner.Text()+strings.Repeat("$", 32))[:32]
	encryptedKey := []byte(enceypt([]byte(MAGIC), keyString))
	err := ioutil.WriteFile(filename, encryptedKey, 0600)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("created " + filename)
	return encryptedKey
}

func readDecryptedKey(filename string) string {
	encryptedKey, err := ioutil.ReadFile(filename)
	if err != nil {
		encryptedKey = createNewKey(filename)
	}
	return deceypt([]byte(MAGIC), string(encryptedKey))
}

func createCfg(filename string) {
	err := ioutil.WriteFile(filename, []byte("{}"), 0644)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("created " + filename)
}

func readCfg(filename string) map[string] string {
	data, err := ioutil.ReadFile(filename)
	cfg := map[string] string {}
	if err != nil {
		createCfg(filename)
		return cfg
	}
	json.Unmarshal(data, &cfg)
	return cfg
}

func readAccessToken(filename string, key string) string {
	cfg := readCfg(filename)
	accessToken := cfg["access_token"]
	if len(accessToken) == 0 {
		return ""
	}
	return deceypt([]byte(key), accessToken)
}

func saveAccessToken(accessToken string, refreshToken string, filename string, key string) {
	cfg := readCfg(filename)
	encryptedAccessToken := enceypt([]byte(key), accessToken)
	cfg["access_token"] = encryptedAccessToken

	if refreshToken != "" {
		encryptedRefreshToken := enceypt([]byte(key), refreshToken)
		cfg["refresh_token"] = encryptedRefreshToken
	}

	saveCfg(filename, cfg)
}

func issueAccessToken(username string, password string, endpoint string) (string, string) {
	resp, err := http.PostForm(endpoint+"/oauth/token",
		url.Values{
		"username": {username},
		"password": {password},
		"client_id": {"categolj2-admin"},
		"client_secret": {"categolj2-secret"},
		"grant_type": {"password"}})
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)

	ret := map[string] string {}
	json.Unmarshal(contents, &ret)

	if (resp.StatusCode != 200) {
		fmt.Println(resp.Status + " (" + ret["error_description"] + ")")
		return "", ""
	}
	return ret["access_token"], ret["refresh_token"]
}

func refreshToken(cfgfile string, endpoint string) {
	cfg := readCfg(cfgfile)
	refreshToken := cfg["refresh_token"]
	resp, err := http.PostForm(endpoint+"/oauth/token",
		url.Values{
		"token": {refreshToken},
		"client_id": {"categolj2-admin"},
		"client_secret": {"categolj2-secret"},
		"grant_type": {"refresh_token"}})
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)

	ret := map[string] string {}
	json.Unmarshal(contents, &ret)

	if (resp.StatusCode != 200) {
		fmt.Println(resp.Status + " (" + ret["error_description"] + ")")
		fmt.Println("clear access token. please re-login.")
		cfg["access_token"] = ""
		cfg["refresh_token"] = ""
		saveCfg(cfgfile, cfg)
		return
	}

	cfg["access_token"] = ret["access_token"]
	cfg["refresh_token"] = ret["refresh_token"]
	saveCfg(cfgfile, cfg)
}

func removeFile(filename string) {
	fmt.Println("remove " + filename)
	os.Remove(filename)
}

func saveCfg(filename string, cfg map[string] string) {
	data, _ := json.Marshal(cfg)
	err := ioutil.WriteFile(filename, data, 0644)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("save " + filename)
	}
}

func checkToken(keyfile string, cfgfile string, endpoint string) string {
	key := readDecryptedKey(keyfile)
	accessToken := readAccessToken(cfgfile, key)
	refreshToken := ""
	if accessToken == "" {
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Print("enter username: ")
		scanner.Scan()
		username := scanner.Text()
		fmt.Print("enter password: ")
		scanner.Scan()
		password := scanner.Text()

		accessToken, refreshToken = issueAccessToken(username, password, endpoint)
		if (accessToken == "") {
			fmt.Println("cannot get access token")
			return ""
		}
		saveAccessToken(accessToken, refreshToken, cfgfile, key)
	}
	return accessToken
}

func checkEndpoint(cfgfile string) string {
	cfg := readCfg(cfgfile)
	endpoint := cfg["endpoint"]
	if len(endpoint) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Print("enter endpoint (ex. http://blog.ik.am): ")
		scanner.Scan()
		endpoint = scanner.Text()
		cfg["endpoint"] = endpoint
		saveCfg(cfgfile, cfg)
	}
	return endpoint
}


func main() {
	var (
		keyfile string
		cfgfile string
		basedir string
	)
	flag.StringVar(&keyfile, "key", os.Getenv("HOME")+"/.categolj2key", "File path to save config")
	flag.StringVar(&cfgfile, "cfg", os.Getenv("HOME")+"/.categolj2cfg", "File path to save key")
	flag.StringVar(&basedir, "d", ".", "File path to store downloaded entries.")
	flag.Usage = func() {
		fmt.Println(`
  NAME:

    catego

  DESCRIPTION:

    CLI frontend for CategoLJ2

  OPTIONS:

    -cfg=<path>              File path to save config. (Default: $HOME/.categolj2cfg)
    -key=<path>              File path to save key. (Default: $HOME/.categolj2key)
    -d=<path>                File path to store downloaded entries. (Default: .) This is used only in case of GET/POST.

  COMMANDS:

    clean                    Clean files.
    rmcfg                    Remove config file.
    refreshtoken             Refresh access token.

    gets <page>              Get entries. 'page' begin with 0.
    get <filename|entryId>   Get entry.
    post <filename|entryId>  Create new entry.
    put <filename|entryId>   Update the entry.
    del <filename|entryId>   Delete the entry.
    template                 Output template entry file.
`[1:])
	}
	flag.Parse()

	cmd := flag.Arg(0)
	switch {
	case cmd == "clean":
		removeFile(keyfile)
		removeFile(cfgfile)
	case cmd == "rmcfg":
		removeFile(cfgfile)
	case cmd == "refreshtoken":
		endpoint := checkEndpoint(cfgfile)
		refreshToken(cfgfile, endpoint)
	case cmd == "gets":
		page, _ := strconv.Atoi(flag.Arg(1))
		endpoint := checkEndpoint(cfgfile)
		accessToken := checkToken(keyfile, cfgfile, endpoint)
		if accessToken != "" {
			getEntries(page, accessToken, endpoint, basedir)
		}
	case cmd == "get":
		filename := strings.TrimSpace(flag.Arg(1))
		endpoint := checkEndpoint(cfgfile)
		accessToken := checkToken(keyfile, cfgfile, endpoint)
		if accessToken != "" {
			getEntry(filename, accessToken, endpoint, basedir)
		}
	case cmd == "post":
		filename := strings.TrimSpace(flag.Arg(1))
		endpoint := checkEndpoint(cfgfile)
		accessToken := checkToken(keyfile, cfgfile, endpoint)
		if accessToken != "" {
			postEntry(filename, accessToken, endpoint, basedir)
		}
	case cmd == "put":
		filename := strings.TrimSpace(flag.Arg(1))
		endpoint := checkEndpoint(cfgfile)
		accessToken := checkToken(keyfile, cfgfile, endpoint)
		if accessToken != "" {
			putEntry(filename, accessToken, endpoint, filepath.Dir(filename))
		}
	case cmd == "del":
		filename := strings.TrimSpace(flag.Arg(1))
		endpoint := checkEndpoint(cfgfile)
		accessToken := checkToken(keyfile, cfgfile, endpoint)
		if accessToken != "" {
			deleteEntry(filename, accessToken, endpoint)
		}
	case cmd == "template":
		fmt.Println(`
title: Title here
category: xxx::yyy::zzz
published: false
updateLastModifiedDate: false
saveInHistory: true

----

Write contents here`[1:])
	default:
		flag.Usage()
	}
}
