package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/flier/gohs/hyperscan"
	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"

	"github.com/klauspost/compress/zstd"
	"github.com/pkg/profile"

	"github.com/akamensky/argparse"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/mxk/go-flowrate/flowrate"
	"github.com/rakyll/magicmime"
	"github.com/streadway/amqp"

	"github.com/cyberdelia/lzo"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"

	_ "net/http/pprof"
)

var ruleNames []string
var fileextensions []string

type Config struct {
	Credentials []struct {
		Domain   string `yaml:"domain"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	} `yaml:"credentials"`
	Paths struct {
		Log_path   string `yaml:"log_path"`
		Image_path string `yaml:"image_path"`
		Tmp_path   string `yaml:"tmp_path"`
	} `yaml:"paths"`
	Quota struct {
		Max_read         int64 `yaml:"max_read"`
		Max_bandwidth    int64 `yaml:"max_bandwidth"`
		Max_memory       int64 `yaml:"max_memory"`
		Max_size_per_reg int64 `yaml:"max_size_per_reg"`
		Timeout          int64 `yaml:"timeout"`
	} `yaml:"quota"`
	Rabbitmq struct {
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		Queue    string `yaml:"queue"`
	} `yaml:"rabbitmq"`
	Num_workers      int  `yaml:"num_workers"`
	Num_requesters   int  `yaml:"num_requesters"`
	Force_reanalysis bool `yaml:"force_reanalysis"`
}

// Struct to hold required input json from AMQP
type Input struct {
	Repository string   `json:"repository"`
	Layer      string   `json:"layer"`
	Urls       []string `json:"urls"`
	Registry   string   `json:"registry"`
}

// Struct to hold meta information and data of matches
type Match struct {
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
	Data  []byte `json:"data"`
	Rule  string `json:"rule"`
}

// Struct to hold meta information and matches of files included in images
type FileInfo struct {
	Meta         *tar.Header `json:"meta"`
	Sha256       string      `json:"sha256"`
	Mime         string      `json:"mime"`
	Matches      []*Match    `json:"matches"`
	File         string      `json:"file"`
	Decompressed *FileInfo   `json:"decompressed"`
	Error        error       `json:"error"`
	Time         time.Time   `json:"time"`
	EndTime      time.Time   `json:"endtime"`

	Deflated []*FileInfo `json:"deflated"`
}

// Struct to hold analysis information on layers
type LayerInfo struct {
	Time    time.Time   `json:"time"`
	EndTime time.Time   `json:"endtime"`
	Source  Input       `json:"source"`
	Files   []*FileInfo `json:"files"`
}

// Struct to hold states of workers
type Worker struct {
	id     int
	config *Config

	reconnect bool
	amqp_conn *amqp.Connection
	amqp_chan *amqp.Channel
	amqp_msgs <-chan amqp.Delivery

	http_client_retry *retryablehttp.Client
	http_client       *http.Client
	http_useragent    string

	mime_decoder *magicmime.Decoder

	hyperscanDb  hyperscan.StreamDatabase
	scratchSpace *hyperscan.Scratch
}

var errImageNA = errors.New("image not available")
var errAuthReqFailed = errors.New("authentication request failed")

// Struct to hold state for saving matches / information in tar gz files
type TarSaver struct {
	path string
	file *os.File

	gzipWriter *gzip.Writer
	tarWriter  *tar.Writer

	opened bool
}

func NewTarSaver(path string) *TarSaver {
	return &TarSaver{path: path, opened: false}
}

// Create new tar gz file to store matches found in images
func (ts *TarSaver) Open() error {
	var err error

	if ts.opened {
		return nil
	}

	ts.file, err = os.Create(ts.path)
	if err != nil {
		return err
	}
	ts.gzipWriter = gzip.NewWriter(ts.file)
	ts.tarWriter = tar.NewWriter(ts.gzipWriter)

	ts.opened = true

	return err
}

func (ts *TarSaver) Close() {
	if ts.opened {
		ts.tarWriter.Flush()
		ts.tarWriter.Close()

		ts.gzipWriter.Flush()
		ts.gzipWriter.Close()
		ts.file.Close()
	}
}

// Add file to tar gz archive
func (ts *TarSaver) AddFromReader(header *tar.Header, content io.Reader) (int64, error) {
	if !ts.opened {
		err := ts.Open()
		if err != nil {
			return 0, err
		}
	}

	err := ts.tarWriter.WriteHeader(header)
	if err != nil {
		return 0, err
	}

	num, err := io.Copy(ts.tarWriter, content)
	if err != nil {
		return 0, err
	}

	return num, err
}

// Remove unwanted characters from filepath ([^A-Za-z0-9._-]) and replace by _
func replaceForPath(in string) string {
	re := regexp.MustCompile("[^A-Za-z0-9._-]")
	return re.ReplaceAllString(in, "_")
}

// Only log on error
func logOnError(level log.Level, err error, i *Input, msg string, v ...interface{}) bool {
	if err != nil {
		logMsg(level, i, fmt.Sprintf("%s: %s", msg, err), v...)
		return true
	}
	return false
}

// Log on error and add id of worker
func (w *Worker) logOnError(level log.Level, err error, i *Input, msg string, v ...interface{}) bool {
	return logOnError(level, err, i, fmt.Sprintf("Worker %d: %s", w.id, msg), v...)
}

// Log message incl. information in Input struct, i.e., registry, repository, layer, and urls
func logMsg(level log.Level, i *Input, msg string, v ...interface{}) {
	if i != nil {
		log.StandardLogger().Logf(level, fmt.Sprintf("%s (registry: %s, repository: %s, layer: %s, urls: %v)", msg, i.Registry, i.Repository, i.Layer, i.Urls), v...)
	} else {
		log.StandardLogger().Logf(level, msg, v...)
	}
}

// Log message and add id of worker
func (w *Worker) logMsg(level log.Level, i *Input, msg string, v ...interface{}) {
	logMsg(level, i, fmt.Sprintf("Worker %d: %s", w.id, msg), v...)
}

func loadConfig(path *string, config *Config) {
	filename, err := filepath.Abs(*path)
	logOnError(log.FatalLevel, err, nil, "Failed to estimate absolute path of config file")
	yamlFile, err := ioutil.ReadFile(filename)
	logOnError(log.FatalLevel, err, nil, "Failed to load config file")
	err = yaml.Unmarshal(yamlFile, config)
	logOnError(log.FatalLevel, err, nil, "Failed to parse yaml")
}

// Create HTTP request and set header fields
func (w *Worker) create_http_request(method string, purl string, body io.Reader) (*http.Request, error) {
	var host string

	req, err := http.NewRequest(method, purl, body)
	if err != nil {
		return req, err
	}

	purl_parsed, err := url.Parse(purl)
	if w.logOnError(log.ErrorLevel, err, nil, "Failed to parse url") {
		host = ""
	} else {
		host = strings.Split(purl_parsed.Host, ":")[0]
	}

	req.Host = host
	req.Header.Set("User-Agent", w.http_useragent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")

	return req, err
}

// Get authentication endpoint from registry if required, i.e., if it responds with HTTP error code 401. Default is "registry.docker.io".
func (w *Worker) get_auth_endpoint(registry string) (string, string, error) {
	reg_service := "registry.docker.io"
	auth_url := ""

	url := fmt.Sprintf("%s/v2/", registry)

	req, err := w.create_http_request(http.MethodGet, url, nil)
	if w.logOnError(log.ErrorLevel, err, nil, "Failed to create Auth Endpoint request: %s", err) {
		return auth_url, reg_service, err
	}

	resp, err := w.http_client.Do(req)
	if w.logOnError(log.ErrorLevel, err, nil, "Failed retrieving auth endpoint: %s", err) {
		if resp != nil {
			w.logMsg(log.InfoLevel, nil, "Header: %v", resp.Header)
		}
		return auth_url, reg_service, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		auth_infos := strings.Split(resp.Header.Get("WWW-Authenticate"), "\"")
		auth_url = auth_infos[1]
		if len(auth_infos) > 3 {
			reg_service = auth_infos[3]
		} else {
			reg_service = ""
		}
	}
	w.logMsg(log.InfoLevel, nil, "Auth URL (%s) and reg_service (%s) retrieved for %s", auth_url, reg_service, registry)

	return auth_url, reg_service, nil
}

type AuthHead struct {
	Token string                      `json:"token"`
	Rest  map[string]*json.RawMessage `json:"-"`
}

// Try to retrieve authentication token from authentication endpoint for specified scope
func (w *Worker) get_auth_token_standard(auth_url string, reg_service string, scope string) (string, bool, error) {
	params := url.Values{}
	params.Add("service", reg_service)
	params.Add("scope", scope)

	req, err := w.create_http_request(http.MethodGet, auth_url, strings.NewReader(params.Encode()))
	if w.logOnError(log.ErrorLevel, err, nil, "Failed creating new GET request") {
		return "", false, err
	}

	resp, err := w.http_client.Do(req)
	if w.logOnError(log.ErrorLevel, err, nil, "Failed to get Auth Head (AUTH): %s", err) {
		if resp != nil {
			w.logMsg(log.InfoLevel, nil, "Header: %v", resp.Header)
		}
		return "", false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		w.logMsg(log.InfoLevel, nil, "Failed to authenticate via AUTH [HTTP %d]", resp.StatusCode)
		return "", false, nil
	}

	var auth_head AuthHead
	err = json.NewDecoder(resp.Body).Decode(&auth_head)
	if w.logOnError(log.ErrorLevel, err, nil, "Failed to decode JSON response") {
		return "", false, nil
	}

	return auth_head.Token, true, nil
}

type OAuth2Head struct {
	AccessToken string                      `json:"access_token"`
	Rest        map[string]*json.RawMessage `json:"-"`
}

// Try to retrieve oauth2 authentication token from authentication endpoint for specified scope
func (w *Worker) get_auth_token_oauth2(auth_url string, reg_service string, scope string) (string, bool, error) {
	params := url.Values{}

	var matching_credentials [][]string

	for _, c := range w.config.Credentials {
		if strings.Contains(auth_url, c.Domain) {
			matching_credentials = append(matching_credentials, []string{c.Username, c.Password})
		}
	}

	used_credentials := matching_credentials[rand.Intn(len(matching_credentials))]

	params.Add("grant_type", "password")
	params.Add("username", used_credentials[0])
	params.Add("password", used_credentials[1])
	params.Add("service", reg_service)
	params.Add("client_id", "dockerengine")
	params.Add("scope", scope)

	req, err := w.create_http_request(http.MethodPost, auth_url, strings.NewReader(params.Encode()))
	if w.logOnError(log.ErrorLevel, err, nil, "Failed to create Auth Head (OAUTH2) request") {
		return "", false, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := w.http_client.Do(req)
	if w.logOnError(log.ErrorLevel, err, nil, "Failed to get Auth Head (OAUTH2): %s", err) {
		if resp != nil {
			w.logMsg(log.InfoLevel, nil, "Header: %v", resp.Header)
		}
		return "", false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		w.logMsg(log.InfoLevel, nil, "Failed to authenticate via OAUTH2 [HTTP %d]", resp.StatusCode)
		return "", false, nil
	}

	var auth_head OAuth2Head
	err = json.NewDecoder(resp.Body).Decode(&auth_head)
	if w.logOnError(log.ErrorLevel, err, nil, "Failed to decode JSON response") {
		return "", false, nil
	}

	return auth_head.AccessToken, true, nil
}

// Authenticate at registry for specified scope, i.e., first get authentication endpoint, then try to retrieve oauth2 token. If no oauth2 token is available, retry getting a standard token.
func (w *Worker) reauthenticate(registry string, scope string) (string, bool, error) {
	auth_url, reg_service, err := w.get_auth_endpoint(registry)
	if auth_url == "" && err == nil {
		return "", false, nil
	} else if err != nil {
		return "", false, err
	}

	token, success, err := w.get_auth_token_oauth2(auth_url, reg_service, scope)
	if err != nil {
		return token, success, err
	}

	if !success {
		token, success, err = w.get_auth_token_standard(auth_url, reg_service, scope)
		if err != nil {
			return token, success, err
		}
	}

	return token, success, nil
}

// Get layer from specified registry and repository in Input struct
func (w *Worker) get_layer_stream(il Input) (io.ReadCloser, error) {
	var urls []string

	urls = append(urls, fmt.Sprintf("%s/v2/%s/blobs/%s", il.Registry, il.Repository, il.Layer))
	urls = append(urls, il.Urls...)

	auth_token, success, err := w.reauthenticate(il.Registry, fmt.Sprintf("repository:%s:pull", il.Repository))
	if err != nil {
		return nil, errAuthReqFailed
	}

	for _, u := range urls {
		req, err := w.create_http_request(http.MethodGet, u, nil)
		if w.logOnError(log.ErrorLevel, err, nil, "Failed creating new GET request") {
			continue
		}

		if success {
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", auth_token))
		}
		resp, err := w.http_client.Do(req)
		if w.logOnError(log.ErrorLevel, err, nil, fmt.Sprintf("Failed to get layer stream from %s: %s", u, err)) {
			if resp != nil {
				w.logMsg(log.InfoLevel, &il, "Header: %v", resp.Header)
			}
			continue
		}

		if resp != nil {
			w.logMsg(log.DebugLevel, &il, "Header of layer stream response: %v")

			if resp.StatusCode == http.StatusOK {
				return resp.Body, nil
			} else {
				w.logMsg(log.InfoLevel, nil, "Retrieved HTTP response with code %d", resp.StatusCode)
			}
		}
	}

	w.logMsg(log.InfoLevel, nil, "Failed to GET layer %s (registry: %s, repository: %s)", il.Layer, il.Registry, il.Repository)
	return nil, errImageNA
}

// Try to decompress from input reader relying on the mime type to identify compression algorithm
func (w *Worker) try_decompress(mime string, in io.Reader) (bool, io.Reader, error) {
	var out_reader io.Reader
	var err error

	switch mime {
	case "application/x-bzip2":
		out_reader = bzip2.NewReader(in)
		if out_reader == nil {
			return false, in, errors.New("creating bzip2 reader failed")
		}
		w.logMsg(log.DebugLevel, nil, "bzip decompression applied")
	case "application/gzip":
		out_reader, err = gzip.NewReader(in)
		if w.logOnError(log.ErrorLevel, err, nil, "Failed trying to decompress file") {
			return false, in, err
		}
		w.logMsg(log.DebugLevel, nil, "gzip decompression applied")
	case "application/x-lzma":
		out_reader, err = lzma.NewReader(in)
		if w.logOnError(log.ErrorLevel, err, nil, "Failed trying to decompress file") {
			return false, in, err
		}
		w.logMsg(log.DebugLevel, nil, "lzma decompression applied")
	case "application/x-lzop":
		out_reader, err = lzo.NewReader(in)
		if w.logOnError(log.ErrorLevel, err, nil, "Failed trying to decompress file") {
			return false, in, err
		}
		w.logMsg(log.DebugLevel, nil, "lzo decompression applied")
	case "application/x-xz":
		out_reader, err = xz.NewReader(in)
		if w.logOnError(log.ErrorLevel, err, nil, "Failed trying to decompress file") {
			return false, in, err
		}
		w.logMsg(log.DebugLevel, nil, "xz decompression applied")
	case "application/x-zstd":
		out_reader, err = zstd.NewReader(in)
		if w.logOnError(log.ErrorLevel, err, nil, "Failed trying to decompress file") {
			return false, in, err
		}
		w.logMsg(log.DebugLevel, nil, "zstd decompression applied")
	case "application/x-lzip":
		out_reader, err = lzma.NewReader(in)
		if w.logOnError(log.ErrorLevel, err, nil, "Failed trying to decompress file") {
			return false, in, err
		}
		w.logMsg(log.DebugLevel, nil, "lzip decompression applied")
	default:
		return false, in, nil
	}

	return true, out_reader, nil
}

// Handle secret scanning in tar file, i.e., analyze each file in a tar file.
func (w *Worker) deflate_handle_tar(reader *tar.Reader, il *Input, file_infos *[]*FileInfo, layerTarSaver *TarSaver, deflate_depth int, path_prefix string) error {
L:
	for {
		header, err := reader.Next()
		switch {
		case err == io.EOF:
			break L
		case err != nil:
			w.logOnError(log.ErrorLevel, err, il, fmt.Sprintf("Cannot interpret tar (path_prefix: %s)", path_prefix))
			return err
		case header == nil:
			continue
		}

		if header.Typeflag == tar.TypeReg {
			file_info := new(FileInfo)

			meta := *header
			meta.Name = path.Join(path_prefix, header.Name)

			file_info.Meta = header
			w.analyze_file(il, file_info, reader, deflate_depth, layerTarSaver, path_prefix)

			*file_infos = append(*file_infos, file_info)
		}
	}
	return nil
}

// Handle secret scanning in tar file, i.e., analyze each file in a tar file.
func (w *Worker) deflate_handle_zip(reader *zip.Reader, il *Input, file_infos *[]*FileInfo, layerTarSaver *TarSaver, deflate_depth int, path_prefix string) {
	for _, f := range reader.File {
		file_info := new(FileInfo)
		file_info.Meta = &tar.Header{
			Name:    path.Join(path_prefix, f.Name),
			Size:    int64(f.UncompressedSize64),
			ModTime: f.Modified,
		}

		f_reader, err := f.Open()
		if w.logOnError(log.ErrorLevel, err, il, "Failed to extract from zip") {
			continue
		}

		w.analyze_file(il, file_info, f_reader, deflate_depth, layerTarSaver, path_prefix)

		*file_infos = append(*file_infos, file_info)
	}
}

// Handle secret scanning in tar and zip files, i.e., check mime type and call specific subroutine.
func (w *Worker) try_deflate(il *Input, fi *FileInfo, in io.Reader, deflate_depth int, layerTarSaver *TarSaver, path_prefix string) (bool, error) {
	if deflate_depth < 1 {
		return false, nil
	}

	switch fi.Mime {
	case "application/x-tar":
		deflated_reader := tar.NewReader(in)
		if deflated_reader == nil {
			return false, errors.New("untarring failed for some reason")
		}
		w.logMsg(log.DebugLevel, il, "Deflating tar")
		err := w.deflate_handle_tar(deflated_reader, il, &fi.Deflated, layerTarSaver, deflate_depth-1, fmt.Sprintf("%s.deflated/", fi.Meta.Name))
		return true, err
	case "application/zip":
		zipped, err := ioutil.ReadAll(io.LimitReader(in, w.config.Quota.Max_read))
		if err != nil && err != io.EOF {
			w.logOnError(log.ErrorLevel, err, il, fmt.Sprintf("Error when handling zip file: %s", fi.Meta.Name))
			fi.Error = err
			return false, err
		}

		deflated_reader, err := zip.NewReader(bytes.NewReader(zipped), int64(len(zipped)))
		if w.logOnError(log.ErrorLevel, err, il, fmt.Sprintf("Error when tryping to deflate zip file: %s", fi.Meta.Name)) {
			fi.Error = err
			return false, err
		}
		w.logMsg(log.DebugLevel, il, "Deflating zip")
		w.deflate_handle_zip(deflated_reader, il, &fi.Deflated, layerTarSaver, deflate_depth-1, fmt.Sprintf("%s.deflated/", fi.Meta.Name))
		return true, nil
	}
	return false, nil
}

// Struct to enable caching of large files, either in memory or on disk. Required to start reading files from the beginning again and again.
type StoredFile struct {
	i  *Input
	fi *FileInfo

	source io.Reader

	fileBackup  bool
	target_path string
	disk_path   string
	buf         *bytes.Buffer

	size   int64
	offset int64

	stored   bool
	finished bool

	writer io.Writer
	reader io.Reader
}

func NewStoredFile(i *Input, fi *FileInfo, source io.Reader, fileBackup bool, path string) *StoredFile {
	new := &StoredFile{
		i:           i,
		fi:          fi,
		buf:         new(bytes.Buffer),
		source:      source,
		fileBackup:  fileBackup,
		target_path: path,
	}

	n, err := io.CopyN(new.buf, source, 4096)
	new.size = n
	new.offset = n
	if err != nil {
		if err == io.EOF {
			new.finished = true
		} else {
			log.Warnf("Error (%s) while reading content file (layer: %s, registry: %s, repository: %s, file %s)", err, new.i.Layer, new.i.Registry, new.i.Repository, new.fi.Meta.Name)
		}
	}

	return new
}

// Enable backup of file either on disk or in memory
func (cb *StoredFile) EnableBackup() {
	if cb.stored {
		return
	}

	logMsg(log.DebugLevel, cb.i, "Enabling backup (%d vs %d)", cb.size, cb.buf.Len())

	if cb.size > int64(cb.buf.Len()) {
		log.Warnf("Storing not impossible anymore, already discarded data (layer: %s, registry: %s, repository: %s, file %s)", cb.i.Layer, cb.i.Registry, cb.i.Repository, cb.fi.Meta.Name)
	}

	if cb.fileBackup {
		err := os.MkdirAll(cb.target_path, 0777)
		if err != nil {
			log.Fatal(err)
		}
		fd, err := ioutil.TempFile(cb.target_path, "tmp_comp")
		if err != nil {
			log.Fatal(err)
		}
		cb.disk_path = fd.Name()

		logMsg(log.DebugLevel, cb.i, "File backup enabled %s", cb.disk_path)

		io.Copy(fd, cb.buf)
		cb.writer = fd
	} else {
		cb.writer = cb.buf
	}

	if !cb.finished {
		logMsg(log.DebugLevel, cb.i, "enabling tee reader")
		cb.source = io.TeeReader(cb.source, cb.writer)
	} else {
		cb.closeWriter()
	}
	cb.stored = true

	target := cb.offset
	cb.newReader()
	cb.Seek(target, io.SeekStart)
}

func (cb *StoredFile) Size() int64 {
	return cb.size
}

func (cb *StoredFile) closeReader() {
	if cb.reader != nil {
		switch v := cb.reader.(type) {
		case io.Closer:
			v.Close()
		}
		cb.reader = nil
	}
}

func (cb *StoredFile) closeWriter() {
	if cb.writer != nil {
		switch v := cb.writer.(type) {
		case io.Closer:
			v.Close()
		}
		cb.writer = nil
	}
}

func (cb *StoredFile) newReader() {
	if cb.size > int64(cb.buf.Len()) && !cb.stored {
		log.Warnf("Creating new reader impossible, already discarded data (layer: %s, registry: %s, repository: %s, file %s)", cb.i.Layer, cb.i.Registry, cb.i.Repository, cb.fi.Meta.Name)
	}

	cb.closeReader()

	if cb.fileBackup && cb.stored {
		logMsg(log.DebugLevel, cb.i, "new reader of filebackup")
		tmpReader, err := os.Open(cb.disk_path)
		logOnError(log.ErrorLevel, err, cb.i, "Failed opening stored tempfile")
		if cb.finished {
			cb.reader = tmpReader
		} else {
			cb.reader = io.MultiReader(tmpReader, cb.source)
		}
	} else {
		if cb.finished {
			logMsg(log.DebugLevel, cb.i, "new reader from bytes (len %d)", cb.buf.Len())
			cb.reader = bytes.NewReader(cb.buf.Bytes())
		} else {
			logMsg(log.DebugLevel, cb.i, "new multireader")
			cb.reader = io.MultiReader(bytes.NewReader(cb.buf.Bytes()), cb.source)
		}
	}

	cb.offset = 0
}

func (cb *StoredFile) Read(p []byte) (int, error) {
	var err error
	if cb.reader == nil {
		cb.newReader()
	}

	rnum, err := cb.reader.Read(p)
	cb.offset += int64(rnum)
	if err != nil && err == io.EOF {
		logMsg(log.DebugLevel, cb.i, "end of file reached (after %d bytes)", cb.offset)
		cb.finished = true
		cb.closeWriter()
	} else if err != nil {
		logOnError(log.ErrorLevel, err, cb.i, fmt.Sprintf("Error reading file %s", cb.fi.Meta.Name))
	}
	cb.size = int64(math.Max(float64(cb.size), float64(cb.offset)))
	logMsg(log.DebugLevel, cb.i, "read to offset %d (before %d). max until now: %d", cb.offset, cb.offset-int64(rnum), cb.size)

	return rnum, err
}

func (cb *StoredFile) CompleteInMemory() bool {
	return cb.finished && !cb.fileBackup
}

func (cb *StoredFile) Buf() []byte {
	return cb.buf.Bytes()
}

func (cb *StoredFile) Destroy() {
	cb.closeReader()

	if cb.disk_path != "" {
		os.Remove(cb.disk_path)
	}
}

func (cb *StoredFile) Seek(offset int64, whence int) (int64, error) {
	var target int64
	var err error = nil

	switch whence {
	case io.SeekStart:
		target = offset
	case io.SeekCurrent:
		target = cb.offset + offset
	default:
		logMsg(log.ErrorLevel, cb.i, fmt.Sprintf("Whence mode %d not supported (file %s)", whence, cb.fi.Meta.Name))
		return 0, errors.New("whence not supported")
	}

	if target < cb.offset {
		cb.newReader()
	}

	if target != cb.offset {
		_, err = io.CopyN(ioutil.Discard, cb, target-cb.offset)
		if err != nil {
			log.Warnf("Error (%s) seeking in file (layer: %s, registry: %s, repository: %s, file %s)", err, cb.i.Layer, cb.i.Registry, cb.i.Repository, cb.fi.Meta.Name)
		}
	}

	return cb.offset, err
}

// Analyze a file from image.
func (w *Worker) analyze_file(il *Input, fi *FileInfo, input io.Reader, deflate_depth int, layerTarSaver *TarSaver, path_prefix string) {
	var err error

	w.logMsg(log.DebugLevel, il, "analyzing file %s (%s)", fi.Meta.Name, path_prefix)

	fi.Time = time.Now()

	h := sha256.New()
	rd := io.TeeReader(io.LimitReader(input, w.config.Quota.Max_read), h)

	// Create stored file; if it is larger than specified size, store it on disk.
	storedFile := NewStoredFile(il, fi, rd, (fi.Meta.Size > w.config.Quota.Max_memory), w.config.Paths.Tmp_path)
	if storedFile.Size() == 0 {
		return
	}

	// Get mime type of file
	fi.Mime, err = w.mime_decoder.TypeByBuffer(storedFile.Buf())
	if w.logOnError(log.ErrorLevel, err, il, fmt.Sprintf("Failed to detect mime type (file %s)", fi.Meta.Name)) {
		fi.Error = err
	}
	w.logMsg(log.DebugLevel, il, "mime type: %s", fi.Mime)

	// First try to decompress
	decompressed, rp_ad, err := w.try_decompress(fi.Mime, storedFile)
	if err != nil {
		fi.Error = err
		logOnError(log.ErrorLevel, err, il, "Error during decompression")
	} else {
		if decompressed {
			fi.Decompressed = &FileInfo{
				Meta: fi.Meta,
			}
			fi.Decompressed.Meta.Size = 0
			// Recursively call this method on a decompressed file.
			w.analyze_file(il, fi.Decompressed, rp_ad, deflate_depth-1, layerTarSaver, fmt.Sprintf("%s.decompressed", path_prefix))
		} else {
			// If we have a zip file, enable backup on disk or in memory here.
			if fi.Mime == "application/zip" {
				storedFile.EnableBackup()
			}
			storedFile.Seek(0, io.SeekStart)

			// Try to deflate zip and tar files.
			deflated, err := w.try_deflate(il, fi, rp_ad, deflate_depth, layerTarSaver, path_prefix)
			if !deflated && err == nil { // we did not try to deflate -> normal matching
				storedFile.EnableBackup()
				storedFile.Seek(0, io.SeekStart)

				// Try to match using HyperScan
				handler := hyperscan.MatchHandler(func(id uint, start, end uint64, _ uint, _ interface{}) error {
					fi.Matches = append(fi.Matches, &Match{Rule: ruleNames[id], Start: start, End: end})
					return nil
				})

				stream, err := w.hyperscanDb.Open(0, w.scratchSpace, handler, nil)
				if w.logOnError(log.ErrorLevel, err, il, fmt.Sprintf("Failed to initialize stream scan of file %s", fi.Meta.Name)) {
					fi.Error = err
					return
				}

				// Match file from image blockwise
				eof_reached := false
				buf := make([]byte, 4096)
				for {
					n, err := storedFile.Read(buf)

					if err != nil && err == io.EOF {
						if n == 0 {
							break
						}
						eof_reached = true
					} else if err != nil {
						logOnError(log.ErrorLevel, err, il, "error reading block")
						break
					}

					if err = stream.Scan(buf[:n]); err != nil {
						logOnError(log.ErrorLevel, err, il, "error scanning block")
						break
					}

					if eof_reached {
						break
					}
				}

				err = stream.Close()
				if w.logOnError(log.ErrorLevel, err, il, fmt.Sprintf("Failed to closing stream scan of file %s", fi.Meta.Name)) {
					fi.Error = err
					return
				}

				if fi.Meta.Size == 0 {
					fi.Meta.Size = storedFile.Size()
				}

				store := false
				for _, ext := range fileextensions {
					if path.Ext(fi.Meta.Name) == ext {
						store = true
					}
				}

				// Store each match for later analysis from stored file (not in this application, see analysis scripts)
				if len(fi.Matches) > 0 || store {
					w.logMsg(log.DebugLevel, il, "%d matches in %d bytes", len(fi.Matches), storedFile.Size())
					// Save the file to tar if it matches
					if layerTarSaver != nil {
						storedFile.Seek(0, io.SeekStart)
						tarMeta := *fi.Meta
						tarMeta.Size = storedFile.Size()

						layerTarSaver.AddFromReader(&tarMeta, storedFile)
					}

					for _, m := range fi.Matches {
						storedFile.Seek(int64(m.Start), io.SeekStart)
						m.Data = make([]byte, m.End-m.Start)
						storedFile.Read(m.Data)
						w.logMsg(log.DebugLevel, il, "%v", m)
					}
				}
			}
		}
	}

	_, err = io.Copy(ioutil.Discard, storedFile)
	w.logOnError(log.ErrorLevel, err, nil, "Error emptying storedFile")

	fi.Sha256 = fmt.Sprintf("%x", h.Sum(nil))

	fi.EndTime = time.Now()

	storedFile.Destroy()

	switch v := rp_ad.(type) {
	case io.Closer:
		v.Close()
	}
}

// Main function of worker. Retrieve input data from AMQP and analyze resp. layer. Also handle AMQP reconnect if connection is lost.
func (w *Worker) work() {
	var err error

	for !w.reconnect {
		time.Sleep(1 * time.Second)
	}
	w.reconnect = false
	w.ConnectAMQP()

	for {
		input_raw, ok := <-w.amqp_msgs
		if !ok {
			w.logMsg(log.WarnLevel, nil, "AMQP channel gone")

			for w.amqp_conn.IsClosed() {
				time.Sleep(30 * time.Second)
				w.logMsg(log.InfoLevel, nil, "Waiting for reconnect to AMQP broker")
			}

			w.ConnectAMQP()
			continue
		}

		var il Input

		err = json.Unmarshal(input_raw.Body, &il)
		w.logOnError(log.ErrorLevel, err, nil, fmt.Sprintf("Error parsing json from queue (%s)", string(input_raw.Body)))
		if err != nil {
			input_raw.Ack(false)
			continue
		}

		var layer_info LayerInfo
		layer_info.Source = il
		layer_info.Time = time.Now()

		if il.Layer == "" {
			w.logMsg(log.WarnLevel, &il, "received empty layer. skipping")
			input_raw.Ack(false)
			continue
		}

		image_log_path := path.Join(w.config.Paths.Log_path, replaceForPath(il.Registry), replaceForPath(il.Layer))
		layer_tmp_path := path.Join(w.config.Paths.Tmp_path, fmt.Sprintf("%s.tgz", replaceForPath(il.Layer)))

		if !w.config.Force_reanalysis {
			if _, err := os.Stat(path.Join(image_log_path, "info.json.gz")); !os.IsNotExist(err) {
				// path/to/whatever exists
				input_raw.Ack(false)
				continue
			}
		}

		if _, err := os.Stat(layer_tmp_path); !os.IsNotExist(err) {
			// path/to/whatever exists
			input_raw.Ack(false)
			continue
		}

		os.MkdirAll(image_log_path, 0777)

		err := func() error {
			w.logMsg(log.InfoLevel, &il, "Start working on layer")

			tgz_layer, err := w.get_layer_stream(il)
			if err != nil {
				return err
			}
			if tgz_layer == nil {
				return errImageNA // When no error occured, but we also did not receive a layer then it is unaccessible for us
			}
			defer tgz_layer.Close()

			err = func() error {

				fd, err := os.Create(layer_tmp_path)
				if err != nil {
					return err
				}
				defer os.Remove(layer_tmp_path)
				defer fd.Close()

				ratelimit_tgz_layer := flowrate.NewReader(tgz_layer, w.config.Quota.Max_bandwidth)
				defer ratelimit_tgz_layer.Close()

				num, err := io.Copy(fd, bufio.NewReader(ratelimit_tgz_layer))
				if w.logOnError(log.ErrorLevel, err, &il, "Error downloading layer to file (read %d bytes): %s", num, err) {
					return err
				}
				w.logMsg(log.DebugLevel, &il, "Retrieved %d bytes", num)

				err = fd.Sync()
				if err != nil {
					return err
				}

				return func() error {
					off, err := fd.Seek(0, 0)
					if off != 0 || err != nil {
						return err
					}

					var uncompressedStream io.ReadCloser
					uncompressedStream, err = gzip.NewReader(fd)
					if w.logOnError(log.ErrorLevel, err, &il, "Cannot decompress gzip") {
						switch {
						case errors.Is(err, gzip.ErrHeader):
							off, err := fd.Seek(0, 0)
							if off != 0 || err != nil {
								return err
							}
							uncompressedStream, err = zlib.NewReader(fd)
							if w.logOnError(log.ErrorLevel, err, &il, "Cannot decompress zlib") {
								return err
							}
						default:
							return err
						}
					}
					defer uncompressedStream.Close()

					layerTarSaver := NewTarSaver(fmt.Sprintf("%s/findings.tar.gz", image_log_path))
					defer layerTarSaver.Close()

					tarReader := tar.NewReader(uncompressedStream)
					return w.deflate_handle_tar(tarReader, &il, &layer_info.Files, layerTarSaver, 3, "")
				}()
			}()

			if !w.logOnError(log.ErrorLevel, err, &il, "Work on layer failed") {
				w.logMsg(log.InfoLevel, &il, "Work on layer done")
			}

			return err
		}()

		layer_info.EndTime = time.Now()

		if err == nil {
			err = func() error {
				json_writer, err := os.Create(path.Join(image_log_path, "info.json.gz"))
				if w.logOnError(log.ErrorLevel, err, &il, "Failed creating json") {
					return err
				}
				defer json_writer.Close()

				layer_info_json_gz_writer := gzip.NewWriter(json_writer)
				defer layer_info_json_gz_writer.Close()

				json_encoder := json.NewEncoder(layer_info_json_gz_writer)
				err = json_encoder.Encode(layer_info)
				if w.logOnError(log.ErrorLevel, err, &il, "Failed encoding json") {
					return err
				}

				return nil
			}()

			if err == nil {
				input_raw.Ack(false)
			}
		} else {
			// For layers from Docker Hub, we retry later on in case of an i/o timeout or file error. For private registries we do not.
			if strings.Contains(il.Registry, "docker.io") {
				if strings.Contains(err.Error(), "i/o timeout") {
					w.logMsg(log.WarnLevel, &il, "we acked although we did not analyze due to error: %s", err.Error())
					input_raw.Ack(false)
					continue
				} else {
					switch {
					case errors.Is(err, tar.ErrHeader), errors.Is(err, zlib.ErrHeader), errors.Is(err, errImageNA), errors.Is(err, errAuthReqFailed), errors.Is(err, io.ErrUnexpectedEOF):
						w.logMsg(log.WarnLevel, &il, "we acked although we did not analyze due to error: %s", err.Error())
						input_raw.Ack(false)
						continue
					}
				}

				w.logMsg(log.InfoLevel, &il, "we were not able to retrieve layer: %s", err.Error())
				input_raw.Reject(true)
			} else {
				w.logMsg(log.WarnLevel, &il, "we acked although we did not analyze due to error: %s", err.Error())
				input_raw.Ack(false)
			}
		}
	}
}

func (w *Worker) ConnectAMQP() {
	var err error

	w.logMsg(log.InfoLevel, nil, "Opening AMQP Channel")

	w.amqp_chan, err = w.amqp_conn.Channel()
	w.logOnError(log.FatalLevel, err, nil, "Failed to open a channel")

	err = w.amqp_chan.Qos(3, 0, false)
	w.logOnError(log.FatalLevel, err, nil, "Failed to set QoS")

	w.amqp_msgs, err = w.amqp_chan.Consume(
		w.config.Rabbitmq.Queue, // queue
		"",                      // consumer
		false,                   // auto-ack
		false,                   // exclusive
		false,                   // no-local
		false,                   // no-wait
		nil,                     // args
	)
	w.logOnError(log.FatalLevel, err, nil, "Failed to register a consumer")

	go func() {
		amqp_err := <-w.amqp_chan.NotifyClose(make(chan *amqp.Error))
		w.logMsg(log.InfoLevel, nil, "AMQP Channel closed: %s (%d). %v/%v", amqp_err.Reason, amqp_err.Code, amqp_err.Server, amqp_err.Recover)
	}()
}

func NewWorker(id int, hyperscanDatabase hyperscan.StreamDatabase, c *Config) *Worker {
	var err error

	w := &Worker{id: id, config: c, reconnect: false}

	w.hyperscanDb = hyperscanDatabase

	w.scratchSpace, err = hyperscan.NewScratch(hyperscanDatabase)
	w.logOnError(log.FatalLevel, err, nil, "Failed to initialize scratch space")

	w.mime_decoder, err = magicmime.NewDecoder(magicmime.MAGIC_MIME_TYPE | magicmime.MAGIC_ERROR)
	w.logOnError(log.FatalLevel, err, nil, "Failed to initialize mime detector")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	w.http_client_retry = retryablehttp.NewClient()
	w.http_client_retry.HTTPClient.Transport = tr

	w.http_client = w.http_client_retry.StandardClient()
	w.http_client.Timeout = 30 * time.Minute

	w.http_useragent = "docker researchscan@rwth-aachen.de"

	w.logMsg(log.DebugLevel, nil, "Initialized")
	return w
}

func connectAmqp(worker []*Worker, config *Config) {
	log.Println("Connecting to AMQP")

	url := fmt.Sprintf("amqp://%s:%s@%s:%d/", config.Rabbitmq.Username, config.Rabbitmq.Password, config.Rabbitmq.Host, config.Rabbitmq.Port)
	conn, err := amqp.DialConfig(url, amqp.Config{
		Heartbeat: 60,
	})
	if logOnError(log.ErrorLevel, err, nil, "Failed to connect to RabbitMQ") {
		return
	}

	for _, w := range worker {
		w.amqp_conn = conn
		w.reconnect = true
	}

	amqp_err := <-conn.NotifyClose(make(chan *amqp.Error))
	logMsg(log.InfoLevel, nil, "AMQP disconnected: %s (%d). %v/%v", amqp_err.Reason, amqp_err.Code, amqp_err.Server, amqp_err.Recover)

	for _, w := range worker {
		w.reconnect = false
	}
}

func main() {
	var worker []*Worker

	// Create new parser object
	parser := argparse.NewParser("dockeranalyzer", "Gets layers from AMQP queue and starts analyzing")
	// Create string flag
	c := parser.String("c", "config", &argparse.Options{Required: false, Help: "Path to config", Default: "/config/config.yaml"})
	s := parser.String("s", "signatures", &argparse.Options{Required: false, Help: "Path to signature file", Default: "/signatures/signatures.yaml"})

	profiling := parser.Flag("", "profiling", &argparse.Options{Required: false, Help: "Enable profiling"})
	debuglevel := parser.Selector("l", "loglevel", []string{"INFO", "DEBUG", "WARN"}, &argparse.Options{Required: false, Help: "Log Level", Default: "INFO"})

	// Parse input
	err := parser.Parse(os.Args)
	if err != nil {
		// In case of error print error and print usage
		// This can also be done by passing -h or --help flags
		fmt.Print(parser.Usage(err))
	}

	if *profiling {
		defer profile.Start(profile.MemProfile).Stop()

		go func() {
			http.ListenAndServe(":8123", nil)
		}()
	}

	var config Config
	loadConfig(c, &config)

	loglevel, err := log.ParseLevel(*debuglevel)
	if err != nil {
		log.Fatalf("Specified log level not allowed: %s", *debuglevel)
	}
	log.SetLevel(loglevel)

	log_f, err := os.Create(fmt.Sprintf("%s/%s.log", config.Paths.Log_path, time.Now().Format(time.RFC3339)))
	logOnError(log.FatalLevel, err, nil, "Cannot create logfile")

	mw := io.MultiWriter(os.Stdout, log_f)
	log.SetOutput(mw)

	conf, err := ioutil.ReadFile(*s)
	logOnError(log.FatalLevel, err, nil, "Failed to open signature file")

	signatures := new(yaml.MapSlice)
	err = yaml.Unmarshal(conf, &signatures)
	logOnError(log.FatalLevel, err, nil, "Failed to parse signature file")

	var hyperscanPatterns hyperscan.Patterns
	for _, m1 := range *signatures {
		main_key := m1.Key.(string)
		switch main_key {
		case "hyperscan":
			id := 0
			for _, m2 := range m1.Value.(yaml.MapSlice) {
				namespace := m2.Key.(string)
				for _, m3 := range m2.Value.(yaml.MapSlice) {
					ruleName := m3.Key.(string)
					ruleRegex := m3.Value.(string)

					// Pattern with `L` flag enable leftmost start of match reporting.
					patternParameter := fmt.Sprintf(`%d:/%s/sL`, id, strings.TrimSpace(ruleRegex))

					// First test pattern
					tmp, err := hyperscan.ParsePattern(patternParameter)
					logOnError(log.FatalLevel, err, nil, fmt.Sprintf("Failed to parse pattern %s", patternParameter))

					_, err = tmp.Build(hyperscan.StreamMode)
					if err != nil {
						log.Warnf("Error building pattern %s (%s): %s", ruleName, namespace, err)
						continue
					}

					p, _ := hyperscan.ParsePattern(patternParameter)
					// then add it for later use

					if !p.IsValid() {
						log.Fatalf("Got invalid pattern %v", p)
					}
					ruleNames = append(ruleNames, namespace+"_"+ruleName)
					hyperscanPatterns = append(hyperscanPatterns, p)
					id++
				}
			}
			log.Infof("Loaded %d hyperscan rules", id+1)
		case "fileextension":
			for _, m2 := range m1.Value.([]interface{}) {
				fileextensions = append(fileextensions, m2.(string))
			}
			log.Infof("Loaded %d fileextensions", len(fileextensions))
		}
	}

	db, err := hyperscan.NewStreamDatabase(hyperscanPatterns...)
	logOnError(log.FatalLevel, err, nil, "Failed to create database")
	defer db.Close()

	log.Debugf("Clearing tmp folder")
	dir, err := ioutil.ReadDir(config.Paths.Tmp_path)
	logOnError(log.FatalLevel, err, nil, "Failed cleaning tmp folder")

	for _, d := range dir {
		os.RemoveAll(path.Join([]string{config.Paths.Tmp_path, d.Name()}...))
	}

	for w_id := 1; w_id <= config.Num_workers; w_id++ {
		w := NewWorker(w_id, db, &config)
		worker = append(worker, w)

		go w.work()
	}

	log.Printf(" [*] Waiting for messages. To exit press CTRL+C")

	for {
		connectAmqp(worker, &config)
		time.Sleep(30 * time.Second)
	}
}
