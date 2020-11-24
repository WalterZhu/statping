package utils

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/go-ping/ping"
	"github.com/statping/statping/types/metrics"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var (
	// Directory returns the current path or the STATPING_DIR environment variable
	Directory string
)

func NotNumber(val string) bool {
	_, err := strconv.ParseInt(val, 10, 64)
	return err != nil
}

// ToInt converts a int to a string
func ToInt(s interface{}) int64 {
	switch v := s.(type) {
	case string:
		val, _ := strconv.Atoi(v)
		return int64(val)
	case []byte:
		val, _ := strconv.Atoi(string(v))
		return int64(val)
	case float32:
		return int64(v)
	case float64:
		return int64(v)
	case int:
		return int64(v)
	case int16:
		return int64(v)
	case int32:
		return int64(v)
	case int64:
		return v
	case uint:
		return int64(v)
	default:
		return 0
	}
}

// ToString converts a int to a string
func ToString(s interface{}) string {
	switch v := s.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%v", v)
	case float32, float64:
		return fmt.Sprintf("%f", v)
	case []byte:
		return string(v)
	case bool:
		return fmt.Sprintf("%t", v)
	case time.Time:
		return v.Format("Monday January _2, 2006 at 03:04PM")
	case time.Duration:
		return v.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

// Command will run a terminal command with 'sh -c COMMAND' and return stdout and errOut as strings
//		in, out, err := Command("sass assets/scss assets/css/base.css")
func Command(name string, args ...string) (string, string, error) {
	testCmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	testCmd.Stdout = &stdout
	testCmd.Stderr = &stderr
	err := testCmd.Start()
	if err != nil {
		return "", "", err
	}
	err = testCmd.Wait()
	if err != nil {
		return "", string(stderr.Bytes()), err
	}
	return string(stdout.Bytes()), string(stderr.Bytes()), nil
}

// copyAndCapture will read a terminal command into bytes
func copyAndCapture(w io.Writer, r io.Reader) ([]byte, error) {
	var out []byte
	buf := make([]byte, 1024, 1024)
	for {
		n, err := r.Read(buf[:])
		if n > 0 {
			d := buf[:n]
			out = append(out, d...)
			_, err := w.Write(d)
			if err != nil {
				return out, err
			}
		}
		if err != nil {
			// Read returns io.EOF at the end of file, which is not an error for us
			if err == io.EOF {
				err = nil
			}
			return out, err
		}
	}
}

// DurationReadable will return a time.Duration into a human readable string
// // t := time.Duration(5 * time.Minute)
// // DurationReadable(t)
// // returns: 5 minutes
func DurationReadable(d time.Duration) string {
	if d.Hours() >= 1 {
		return fmt.Sprintf("%0.0f hours", d.Hours())
	} else if d.Minutes() >= 1 {
		return fmt.Sprintf("%0.0f minutes", d.Minutes())
	} else if d.Seconds() >= 1 {
		return fmt.Sprintf("%0.0f seconds", d.Seconds())
	}
	return d.String()
}

// HttpRequest is a global function to send a HTTP request
// // url - The URL for HTTP request
// // method - GET, POST, DELETE, PATCH
// // content - The HTTP request content type (text/plain, application/json, or nil)
// // headers - An array of Headers to be sent (KEY=VALUE) []string{"Authentication=12345", ...}
// // body - The body or form data to send with HTTP request
// // timeout - Specific duration to timeout on. time.Duration(30 * time.Seconds)
// // You can use a HTTP Proxy if you HTTP_PROXY environment variable
func HttpRequest(endpoint, method string, contentType interface{}, headers []string, body io.Reader, timeout time.Duration, verifySSL bool, customTLS *tls.Config) ([]byte, *http.Response, error) {
	var err error
	var req *http.Request
	if method == "" {
		method = "GET"
	}
	t1 := Now()
	if req, err = http.NewRequest(method, endpoint, body); err != nil {
		return nil, nil, err
	}
	// set default headers so end user can overwrite them if needed
	//req.Header.Set("User-Agent", "Statping")
	//req.Header.Set("Statping-Version", Params.GetString("VERSION"))
	if contentType != nil {
		req.Header.Set("Content-Type", contentType.(string))
	}

	verifyHost := req.URL.Hostname()
	for _, h := range headers {
		keyVal := strings.SplitN(h, "=", 2)
		if len(keyVal) == 2 {
			if keyVal[0] != "" && keyVal[1] != "" {
				if strings.ToLower(keyVal[0]) == "host" {
					req.Host = strings.TrimSpace(keyVal[1])
					verifyHost = req.Host
				} else {
					req.Header.Set(keyVal[0], keyVal[1])
				}
			}
		}
	}

	var resp *http.Response
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: timeout,
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !verifySSL,
			ServerName:         verifyHost,
			Renegotiation:      tls.RenegotiateOnceAsClient,
		},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: timeout,
		TLSHandshakeTimeout:   timeout,
		Proxy:                 http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// redirect all connections to host specified in url
			addr = strings.Split(req.URL.Host, ":")[0] + addr[strings.LastIndex(addr, ":"):]
			return dialer.DialContext(ctx, network, addr)
		},
	}
	//if Params.GetString("HTTP_PROXY") != "" {
	//	proxyUrl, err := url.Parse(Params.GetString("HTTP_PROXY"))
	//	if err != nil {
	//		return nil, nil, err
	//	}
	//	transport.Proxy = http.ProxyURL(proxyUrl)
	//}
	if customTLS != nil {
		transport.TLSClientConfig.RootCAs = customTLS.RootCAs
		transport.TLSClientConfig.Certificates = customTLS.Certificates
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	if req.Header.Get("Redirect") != "true" {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
		req.Header.Del("Redirect")
	}

	if resp, err = client.Do(req); err != nil {
		return nil, resp, err
	}
	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, resp, err
	}

	// record HTTP metrics
	metrics.Histo("bytes", float64(len(contents)), endpoint, method)
	metrics.Histo("duration", Now().Sub(t1).Seconds(), endpoint, method)

	return contents, resp, err
}

// 输入host返回DNS耗费的时间，如输入域名有错误，或不存在的域名返回时间为-1
// 使用系统DNS服务器地址，不能设置DNS服务器地址
// 不可设置DNS请求超时时间
// 不存在DNS缓存
// 将来可能需要cgo重写本方法
func DNSCheck(host string, timeout time.Duration) ([]string, time.Duration, error) {
	t1 := time.Now()
	address, err := net.LookupHost(host)
	if err != nil {
		return nil, timeout, err
	}
	return address, time.Now().Sub(t1), nil
}

// 输入：host域名，count次数，timeout超时时间。返回：平均请求时间，如域名有误或者超时返回-1
// 使用OS的DNS服务地址
func ICMPCheck(host string, count int, timeout time.Duration) (time.Duration, error) {
	pinger, err := ping.NewPinger(host)
	if err != nil {
		return timeout, err
	}
	pinger.Count = count
	pinger.Interval = 100*time.Millisecond
	pinger.Timeout = timeout
	pinger.SetPrivileged(false)

	err = pinger.Run()
	if err != nil {
		return timeout, err
	}
	stats := pinger.Statistics()
	return stats.AvgRtt, err
}
