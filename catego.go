package main

import (
	"fmt"
	"flag"
	"strconv"
	"strings"
	"log"
	"time"
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
)

type Entry struct {
	EntryId        int64 `json:"entryId"`
	Title          string `json:"title"`
	Contents       string `json:"contents"`
	CreatedDate    time.Time `json:"createdDate"`
	Format         string `json:"format"`
	CategoryString string `json:"categoryString"`
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

func (entry* Entry) Save() {
	if (entry.EntryId < 1) {
		fmt.Println("cannot save")
		return
	}

	filename := fmt.Sprintf("%d.%s", entry.EntryId, entry.Format)
	f, _ := os.Create(filename)
	defer f.Close()
	f.WriteString("title: " + entry.Title + "\n")
	f.WriteString("category: " + entry.CategoryString + "\n")
	f.WriteString("\n")
	f.WriteString("----\n")
	f.WriteString("\n")
	f.WriteString(entry.Contents)
	f.Sync()
	fmt.Println("wrote " + filename)
}

func getEntries(page int) {
	fmt.Println("download page", page)
	var entryPage EntryPage
	GetForEntity(fmt.Sprintf("http://blog.ik.am/api/v1/entries/?page=%d", page))(&entryPage)
	for _, entry := range entryPage.Content {
		entry.Save()
	}
}

func getEntry(filename string) {
	entryId, _ := getEntryIdAndFormat(filename)

	fmt.Println("download ", entryId)
	var entry Entry
	GetForEntity("http://blog.ik.am/api/v1/entries/" + entryId)(&entry)
	entry.Save()
}

func postEntry(filename string) {
	_, format := getEntryIdAndFormat(filename)

	var entry Entry;
	entry.Format = format
	entry.Contents, _ = readContents(filename)

	log.Println(entry)
}

func putEntry(filename string) {
	entryId, format := getEntryIdAndFormat(filename)

	var entry Entry
	var header *Header
	entry.EntryId, _ = strconv.ParseInt(entryId, 0, 32)
	entry.Format = format
	entry.Contents, header = readContents(filename)
	entry.Title = header.Get("title")
	entry.CategoryString = header.Get("category")

	log.Println(entry)
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

func GetForEntity(url string) func(v interface{}) error {
	response, err := http.Get(url);
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}

	return func(v interface{}) error {
		return json.Unmarshal(contents, v)
	}
}

func readContents(filename string) (string, *Header) {
	f, err := os.Open(filename)
	if err != nil {
		fmt.Println(filename + " is not found!")
		os.Exit(1)
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
			break;
		}

		if (isReadingHeader) {
			if header.IsHeader(line) {
				header.ParseLine(line)
			} else if header.IsHeaderFinished(line) {
				isReadingHeader = false
				fmt.Println("header ", header.data)
			}
			continue
		}
		contents += line
	}


	return contents, header
}

func deleteEntry(filename string) {
	entryId, _ := getEntryIdAndFormat(filename)
	log.Println("delete " + entryId)
}

func getEntryIdAndFormat(filename string) (string, string) {
	result := strings.Split(filename, ".")
	size := len(result)
	if size == 0 {
		panic("<filename> is not specified!")
	} else if size == 1 {
		return filename, "md"
	}
	entryId := strings.Join(result[:size-1], ".")
	format := result[size - 1:][0]
	return entryId, format
}

// encrypt string to base64 crypto using AES
func Encrypt(key []byte, text string) string {
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
func Decrypt(key []byte, cryptoText string) string {
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
	fmt.Print("enter key to encrypt: ")
	scanner.Scan()
	keyString := (scanner.Text()+strings.Repeat("$", 32))[:32]
	encryptedKey := []byte(Encrypt([]byte(MAGIC), keyString))
	err := ioutil.WriteFile(filename, encryptedKey, 0644)
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
	return Decrypt([]byte(MAGIC), string(encryptedKey))
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
	return Decrypt([]byte(key), accessToken)
}

func saveAccessToken(token string, filename string, key string) {
	encryptedToken := Encrypt([]byte(key), token)
	cfg := readCfg(filename)
	cfg["access_token"] = encryptedToken

	data, _ := json.Marshal(cfg)
	err := ioutil.WriteFile(filename, data, 0644)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("save " + filename)
}

func main() {
	flag.Parse()

	keyfile := ".categolj2key"
	cfgfile := ".categolj2cfg"
	key := readDecryptedKey(keyfile)
	token := readAccessToken(cfgfile, key)
	if token == "" {
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Print("enter access token: ")
		scanner.Scan()
		saveAccessToken(scanner.Text(), cfgfile, key)
	}
	fmt.Println(token)

	cmd := flag.Arg(0)
	switch {
	case cmd == "gets":
		page, _ := strconv.Atoi(flag.Arg(1))
		getEntries(page)
	case cmd == "get":
		filename := strings.TrimSpace(flag.Arg(1))
		getEntry(filename)
	case cmd == "post":
		filename := strings.TrimSpace(flag.Arg(1))
		postEntry(filename)
	case cmd == "put":
		filename := strings.TrimSpace(flag.Arg(1))
		putEntry(filename)
	case cmd == "del":
		filename := strings.TrimSpace(flag.Arg(1))
		deleteEntry(filename)
	}
}
