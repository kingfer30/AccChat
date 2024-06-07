package chatgpt

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"freechatgpt/internal/proxys"
	"freechatgpt/internal/tokens"
	"freechatgpt/typings"
	chatgpt_types "freechatgpt/typings/chatgpt"
	"freechatgpt/util"
	"io"
	"log"
	"math/rand"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "time/tzdata"

	"github.com/PuerkitoBio/goquery"
	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/sha3"

	chatgpt_response_converter "freechatgpt/conversion/response/chatgpt"

	official_types "freechatgpt/typings/official"
)

var (
	client              tls_client.HttpClient
	hostURL, _          = url.Parse("https://chatgpt.com")
	API_REVERSE_PROXY   = os.Getenv("API_REVERSE_PROXY")
	FILES_REVERSE_PROXY = os.Getenv("FILES_REVERSE_PROXY")
	userAgent           = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
	performanceNow      = time.Now()
	timeLocation, _     = time.LoadLocation("Asia/Shanghai")
	timeLayout          = "Mon Jan 2 2006 15:04:05"
	cachedHardware      = 0
	cachedSid           = uuid.NewString()
	cachedScripts       = []string{}
	cachedDpl           = ""
	RetryTimes          = 0
	navigatorFuc        = []string{"vendorSub−", "productSub−20030107", "vendor−Google Inc.", "maxTouchPoints−0", "scheduling−[object Scheduling]", "userActivation−[object UserActivation]", "doNotTrack−undefined", "geolocation−[object Geolocation]", "connection−[object NetworkInformation]", "plugins−[object PluginArray]", "mimeTypes−[object MimeTypeArray]", "pdfViewerEnabled−true", "webkitTemporaryStorage−[object DeprecatedStorageQuota]", "webkitPersistentStorage−[object DeprecatedStorageQuota]", "hardwareConcurrency−2", "cookieEnabled−true", "appCodeName−Mozilla", "appName−Netscape", "language−en-US", "languages−en-US", "onLine−true", "webdriver−false", "getGamepads−function getGamepads() { [native code] }", "javaEnabled−function javaEnabled() { [native code] }", "sendBeacon−function sendBeacon() { [native code] }", "vibrate−function vibrate() { [native code] }", "bluetooth−[object Bluetooth]", "clipboard−[object Clipboard]", "credentials−[object CredentialsContainer]", "keyboard−[object Keyboard]", "managed−[object NavigatorManagedData]", "mediaDevices−[object MediaDevices]", "storage−[object StorageManager]", "serviceWorker−[object ServiceWorkerContainer]", "virtualKeyboard−[object VirtualKeyboard]", "wakeLock−[object WakeLock]", "deviceMemory−8", "ink−[object Ink]", "hid−[object HID]", "locks−[object LockManager]", "mediaCapabilities−[object MediaCapabilities]", "mediaSession−[object MediaSession]", "permissions−[object Permissions]", "presentation−[object Presentation]", "serial−[object Serial]", "usb−[object USB]", "windowControlsOverlay−[object WindowControlsOverlay]", "xr−[object XRSystem]", "userAgentData−[object NavigatorUAData]", "canShare−function canShare() { [native code] }", "share−function share() { [native code] }", "clearAppBadge−function clearAppBadge() { [native code] }", "getBattery−function getBattery() { [native code] }", "getUserMedia−function getUserMedia() { [native code] }", "requestMIDIAccess−function requestMIDIAccess() { [native code] }", "requestMediaKeySystemAccess−function requestMediaKeySystemAccess() { [native code] }", "setAppBadge−function setAppBadge() { [native code] }", "webkitGetUserMedia−function webkitGetUserMedia() { [native code] }", "getInstalledRelatedApps−function getInstalledRelatedApps() { [native code] }", "registerProtocolHandler−function registerProtocolHandler() { [native code] }", "unregisterProtocolHandler−function unregisterProtocolHandler() { [native code] }"}
	windowParam         = []string{"0", "window", "self", "document", "name", "location", "customElements", "history", "navigation", "locationbar", "menubar", "personalbar", "scrollbars", "statusbar", "toolbar", "status", "closed", "frames", "length", "top", "opener", "parent", "frameElement", "navigator", "origin", "external", "screen", "innerWidth", "innerHeight", "scrollX", "pageXOffset", "scrollY", "pageYOffset", "visualViewport", "screenX", "screenY", "outerWidth", "outerHeight", "devicePixelRatio", "clientInformation", "screenLeft", "screenTop", "styleMedia", "onsearch", "isSecureContext", "trustedTypes", "performance", "onappinstalled", "onbeforeinstallprompt", "crypto", "indexedDB", "sessionStorage", "localStorage", "onbeforexrselect", "onabort", "onbeforeinput", "onblur", "oncancel", "oncanplay", "oncanplaythrough", "onchange", "onclick", "onclose", "oncontextlost", "oncontextmenu", "oncontextrestored", "oncuechange", "ondblclick", "ondrag", "ondragend", "ondragenter", "ondragleave", "ondragover", "ondragstart", "ondrop", "ondurationchange", "onemptied", "onended", "onerror", "onfocus", "onformdata", "oninput", "oninvalid", "onkeydown", "onkeypress", "onkeyup", "onload", "onloadeddata", "onloadedmetadata", "onloadstart", "onmousedown", "onmouseenter", "onmouseleave", "onmousemove", "onmouseout", "onmouseover", "onmouseup", "onmousewheel", "onpause", "onplay", "onplaying", "onprogress", "onratechange", "onreset", "onresize", "onscroll", "onsecuritypolicyviolation", "onseeked", "onseeking", "onselect", "onslotchange", "onstalled", "onsubmit", "onsuspend", "ontimeupdate", "ontoggle", "onvolumechange", "onwaiting", "onwebkitanimationend", "onwebkitanimationiteration", "onwebkitanimationstart", "onwebkittransitionend", "onwheel", "onauxclick", "ongotpointercapture", "onlostpointercapture", "onpointerdown", "onpointermove", "onpointerrawupdate", "onpointerup", "onpointercancel", "onpointerover", "onpointerout", "onpointerenter", "onpointerleave", "onselectstart", "onselectionchange", "onanimationend", "onanimationiteration", "onanimationstart", "ontransitionrun", "ontransitionstart", "ontransitionend", "ontransitioncancel", "onafterprint", "onbeforeprint", "onbeforeunload", "onhashchange", "onlanguagechange", "onmessage", "onmessageerror", "onoffline", "ononline", "onpagehide", "onpageshow", "onpopstate", "onrejectionhandled", "onstorage", "onunhandledrejection", "onunload", "crossOriginIsolated", "scheduler", "alert", "atob", "blur", "btoa", "cancelAnimationFrame", "cancelIdleCallback", "captureEvents", "clearInterval", "clearTimeout", "close", "confirm", "createImageBitmap", "fetch", "find", "focus", "getComputedStyle", "getSelection", "matchMedia", "moveBy", "moveTo", "open", "postMessage", "print", "prompt", "queueMicrotask", "releaseEvents", "reportError", "requestAnimationFrame", "requestIdleCallback", "resizeBy", "resizeTo", "scroll", "scrollBy", "scrollTo", "setInterval", "setTimeout", "stop", "structuredClone", "webkitCancelAnimationFrame", "webkitRequestAnimationFrame", "chrome", "credentialless", "caches", "cookieStore", "ondevicemotion", "ondeviceorientation", "ondeviceorientationabsolute", "launchQueue", "onbeforematch", "getScreenDetails", "queryLocalFonts", "showDirectoryPicker", "showOpenFilePicker", "showSaveFilePicker", "originAgentCluster", "speechSynthesis", "oncontentvisibilityautostatechange", "openDatabase", "webkitRequestFileSystem", "webkitResolveLocalFileSystemURL", "webpackChunk_N_E", "__next_set_public_path__", "next", "__NEXT_DATA__", "__SSG_MANIFEST_CB", "__NEXT_P", "_N_E", "DD_RUM", "regeneratorRuntime", "__REACT_INTL_CONTEXT__", "_", "filterCSS", "filterXSS", "__SEGMENT_INSPECTOR__", "__NEXT_PRELOADREADY", "Intercom", "__MIDDLEWARE_MATCHERS", "__BUILD_MANIFEST", "__SSG_MANIFEST", "__STATSIG_SDK__", "__STATSIG_JS_SDK__", "__STATSIG_RERENDER_OVERRIDE__", "_oaiHandleSessionExpired", "__intercomAssignLocation", "__intercomReloadLocation"}
	documentParam       = []string{"location", "_reactListeningzfarkvlqj1k"}
	cachedRequireProof  = ""
	requirementsSeed    = strconv.FormatFloat(rand.Float64(), 'f', -1, 64)
)

func init() {
	cores := []int{8, 12, 16, 24}
	screens := []int{3000, 4000, 6000}
	rand.New(rand.NewSource(time.Now().UnixNano()))
	core := cores[rand.Intn(4)]
	rand.New(rand.NewSource(time.Now().UnixNano()))
	screen := screens[rand.Intn(3)]
	cachedHardware = core + screen

	retryTimetxt := os.Getenv("RETRY_TIME")
	if retryTimetxt == "" {
		RetryTimes = 2
	} else {
		RetryTimes, _ = strconv.Atoi(retryTimetxt)
	}

	envClientProfileStr := os.Getenv("CLIENT_PROFILE")
	var clientProfile profiles.ClientProfile
	if profile, ok := profiles.MappedTLSClients[envClientProfileStr]; ok {
		clientProfile = profile
	} else {
		clientProfile = profiles.Okhttp4Android13
	}
	envUserAgent := os.Getenv("UA")
	if envUserAgent != "" {
		userAgent = envUserAgent
	}
	client, _ = tls_client.NewHttpClient(tls_client.NewNoopLogger(), []tls_client.HttpClientOption{
		tls_client.WithCookieJar(tls_client.NewCookieJar()),
		tls_client.WithTimeoutSeconds(600),
		tls_client.WithClientProfile(clientProfile),
	}...)
}

func newRequest(method string, url string, body io.Reader, secret *tokens.Secret, deviceId string) (*http.Request, error) {
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return &http.Request{}, err
	}
	request.Header.Set("Connection", "close")
	request.Header.Set("Proxy-Connection", "close")
	request.Header.Set("User-Agent", userAgent)
	request.Header.Set("Accept", "*/*")
	request.Header.Set("Oai-Device-Id", deviceId)
	request.Header.Set("Oai-Language", "zh-CN")
	if secret.Token != "" {
		request.Header.Set("Authorization", "Bearer "+secret.Token)
	}
	if secret.PUID != "" {
		request.Header.Set("Cookie", "_puid="+secret.PUID+";")
	}
	if secret.TeamUserID != "" {
		request.Header.Set("Chatgpt-Account-Id", secret.TeamUserID)
	}
	return request, nil
}

func SetOAICookie(uuid string) {
	client.GetCookieJar().SetCookies(hostURL, []*http.Cookie{{
		Name:  "oai-did",
		Value: uuid,
	}, {
		Name:  "oai-dm-tgt-c-240329",
		Value: "2024-04-02",
	}, {
		Name:  "oai-hlib",
		Value: "true",
	}})
}

type ProofWork struct {
	Difficulty string `json:"difficulty,omitempty"`
	Required   bool   `json:"required"`
	Seed       string `json:"seed,omitempty"`
}

func getParseTime() string {
	now := time.Now()
	now = now.In(timeLocation)
	return now.Format(timeLayout) + " GMT+0800 (中国标准时间)"
}
func InitScriptDpl() {
	for {
		log.Println("获取最新Script脚本")
		getDpl()
		log.Printf("获取完成, 当前文件数: %d", len(cachedScripts))
		time.Sleep(3 * time.Hour)
	}
}
func getDpl() {
	proxy := proxys.GetProxyIP()
	if proxy != "" {
		client.SetProxy(proxy)
	}
	request, err := http.NewRequest(http.MethodGet, "https://chatgpt.com/?oai-dm=1", nil)
	request.Header.Set("User-Agent", userAgent)
	request.Header.Set("Accept", "*/*")
	if err != nil {
		return
	}
	response, err := client.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	doc, _ := goquery.NewDocumentFromReader(response.Body)
	cachedScripts = make([]string, 0)
	inited := false
	doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
		src, exists := s.Attr("src")
		if exists {
			cachedScripts = append(cachedScripts, src)
			if !inited {
				idx := strings.Index(src, "dpl")
				if idx >= 0 {
					cachedDpl = src[idx:]
					inited = true
				}
			}
		}
	})
}
func getConfig() []interface{} {
	var script string
	if len(cachedScripts) == 0 {
		script = "https://cdn.oaistatic.com/_next/static/chunks/polyfills-78c92fac7aa8fdd8.js?dpl=33ba01fcc2056925ff4a17016b4fa07d781e2db8"
	} else {
		script = cachedScripts[rand.Intn(len(cachedScripts))]
	}
	if cachedDpl == "" {
		cachedDpl = "dpl=33ba01fcc2056925ff4a17016b4fa07d781e2db8"
	}
	rand.New(rand.NewSource(time.Now().UnixNano()))
	navigator := navigatorFuc[rand.Intn(len(navigatorFuc))]
	rand.New(rand.NewSource(time.Now().UnixNano()))
	document := documentParam[rand.Intn(len(documentParam))]
	rand.New(rand.NewSource(time.Now().UnixNano()))
	window := windowParam[rand.Intn(len(windowParam))]
	rand.New(rand.NewSource(time.Now().UnixNano()))
	uuid := uuid.New()
	timeNum := (float64(time.Since(performanceNow).Nanoseconds()) + rand.Float64()) / 1e6
	return []interface{}{cachedHardware, getParseTime(), int64(2172649472), 0, userAgent, script, cachedDpl,
		"en-US", "en-US", 0, navigator, document, window, timeNum, uuid}
}
func CalcProofToken(prefix string, seed string, diff string) string {
	token, err := util.RedisHashGet("ProofToken", seed)
	if token != "" && err == nil {
		return prefix + token
	}

	config := getConfig()
	diffLen := len(diff)
	hasher := sha3.New512()
	calcTime := time.Now()
	for i := 0; i < 500000; i++ {
		config[3] = i
		// spend := (float64(time.Since(performanceNow).Nanoseconds()) + rand.Float64()) / 1e6
		// config[9] = math.Round(float64(spend))
		config[9] = (i + 2) / 2
		json, _ := json.Marshal(config)
		base := base64.StdEncoding.EncodeToString(json)
		hasher.Write([]byte(seed + base))
		hash := hasher.Sum(nil)
		hasher.Reset()
		if hex.EncodeToString(hash[:diffLen])[:diffLen] <= diff {
			cost := time.Since(calcTime)
			if cost > time.Second*5 {
				log.Printf("Slowly CalcProofToken: seed: %s, diff: %s, round: %d, time: %d", seed, diff, i, cost*time.Second)
			}
			token = base
			break
		}
	}
	if token == "" {
		log.Printf("ProofToken计算失败, Seed: %s, Difficulty: %s", seed, diff)
		token = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D" + base64.StdEncoding.EncodeToString([]byte(`"`+seed+`"`))
	} else {
		if ok, _ := util.RedisHExists("ProofToken", seed); !ok {
			util.RedisHashSet("ProofToken", seed, token, 60*60*24)
		}
	}
	return prefix + token
}

type ChatRequire struct {
	Token  string    `json:"token"`
	Proof  ProofWork `json:"proofofwork,omitempty"`
	Arkose struct {
		Required bool   `json:"required"`
		DX       string `json:"dx,omitempty"`
	} `json:"arkose"`
	ForceLogin bool `json:"force_login,omitempty"`
}

func CheckRequire(secret *tokens.Secret, deviceId string, proxy string) *ChatRequire {
	if proxy != "" {
		client.SetProxy(proxy)
	}
	if cachedRequireProof == "" {
		cachedRequireProof = CalcProofToken("gAAAAAC", requirementsSeed, "0")
	}
	body := bytes.NewBuffer([]byte(`{"p":"` + cachedRequireProof + `"}`))
	var apiUrl string
	if secret.Token == "" {
		apiUrl = "https://chatgpt.com/backend-anon/sentinel/chat-requirements"
	} else {
		apiUrl = "https://chatgpt.com/backend-api/sentinel/chat-requirements"
	}

	var response *http.Response
	for i := 0; i < 10; i++ {
		request, err := newRequest(http.MethodPost, apiUrl, body, secret, deviceId)
		if err != nil {
			return nil
		}
		request.Header.Set("Content-Type", "application/json")
		response, err = client.Do(request)
		if err != nil {
			return nil
		}
		if response != nil && (response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden ||
			response.StatusCode == http.StatusGatewayTimeout || response.StatusCode == http.StatusServiceUnavailable ||
			response.StatusCode == http.StatusInternalServerError) {
			//关闭当前资源
			response.Body.Close()
		} else {
			break
		}
	}
	var require ChatRequire
	var error_response map[string]interface{}
	defer response.Body.Close()
	bodyByte, err := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		log.Printf("check-requirement失败: %s:%s", response.Status, string(bodyByte))
	}
	if err != nil {
		return nil
	}
	err = json.Unmarshal(bodyByte, &require)
	if err != nil {
		err = json.Unmarshal(bodyByte, &error_response)
		if err != nil {
			return nil
		}
		log.Printf("check-requirement失败原因: %s:%v", response.Status, error_response)
		return nil
	}
	if require.ForceLogin {
		return nil
	}
	return &require
}

var urlAttrMap = make(map[string]string)

type urlAttr struct {
	Url         string `json:"url"`
	Attribution string `json:"attribution"`
}

func getURLAttribution(secret *tokens.Secret, deviceId string, url string) string {
	request, err := newRequest(http.MethodPost, "https://chatgpt.com/backend-api/attributions", bytes.NewBuffer([]byte(`{"urls":["`+url+`"]}`)), secret, deviceId)
	if err != nil {
		return ""
	}
	request.Header.Set("Content-Type", "application/json")
	if err != nil {
		return ""
	}
	response, err := client.Do(request)
	if err != nil {
		return ""
	}
	defer response.Body.Close()
	var attr urlAttr
	err = json.NewDecoder(response.Body).Decode(&attr)
	if err != nil {
		return ""
	}
	return attr.Attribution
}

func IsRetryError(err string) bool {
	if strings.Contains(err, "EOF") {
		return true
	}
	if strings.Contains(err, "connection reset by peer") {
		return true
	}
	return false
}

func POSTconversation(message chatgpt_types.ChatGPTRequest, secret *tokens.Secret, deviceId string, chat_token string, arkoseToken string, proofToken string, proxy string) (*http.Response, error) {
	if proxy != "" {
		client.SetProxy(proxy)
	}
	var apiUrl string
	if secret.Token == "" {
		apiUrl = "https://chatgpt.com/backend-anon/conversation"
	} else {
		apiUrl = "https://chatgpt.com/backend-api/conversation"
	}
	if API_REVERSE_PROXY != "" {
		apiUrl = API_REVERSE_PROXY
	}
	// JSONify the body and add it to the request
	body_json, err := json.Marshal(message)
	if err != nil {
		return &http.Response{}, err
	}

	request, err := newRequest(http.MethodPost, apiUrl, bytes.NewReader(body_json), secret, deviceId)
	if err != nil {
		return &http.Response{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	if arkoseToken != "" {
		request.Header.Set("Openai-Sentinel-Arkose-Token", arkoseToken)
	}
	if chat_token != "" {
		request.Header.Set("Openai-Sentinel-Chat-Requirements-Token", chat_token)
	}
	if proofToken != "" {
		request.Header.Set("Openai-Sentinel-Proof-Token", proofToken)
	}
	request.Header.Set("Origin", "https://chatgpt.com")
	request.Header.Set("Referer", "https://chatgpt.com/")
	if err != nil {
		return &http.Response{}, err
	}
	response, err := client.Do(request)
	return response, err
}

// Returns whether an error was handled
func Handle_request_error(c *gin.Context, response *http.Response, bodyBytes []byte) bool {
	if response.StatusCode != 200 {
		// Try read response body as JSON
		var error_response map[string]interface{}
		err := json.Unmarshal(bodyBytes, &error_response)
		if err != nil {
			msg := "Unknown error"
			if error_response != nil && error_response["detail"] != "" {
				msg = error_response["detail"].(string)
			}
			c.JSON(500, gin.H{"error": gin.H{
				"message": msg,
				"type":    "internal_server_error",
				"param":   nil,
				"code":    "500",
			}})
			return true
		}
		c.JSON(response.StatusCode, gin.H{"error": gin.H{
			"message": error_response["detail"],
			"type":    response.Status,
			"param":   nil,
			"code":    "error",
		}})
		return true
	}
	return false
}

type ContinueInfo struct {
	ConversationID string `json:"conversation_id"`
	ParentID       string `json:"parent_id"`
}

type fileInfo struct {
	DownloadURL string `json:"download_url"`
	Status      string `json:"status"`
}

func GetImageSource(wg *sync.WaitGroup, url string, prompt string, secret *tokens.Secret, deviceId string, idx int, imgSource []string) {
	defer wg.Done()
	request, err := newRequest(http.MethodGet, url, nil, secret, deviceId)
	if err != nil {
		return
	}
	response, err := client.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	var file_info fileInfo
	err = json.NewDecoder(response.Body).Decode(&file_info)
	if err != nil || file_info.Status != "success" {
		return
	}
	imgSource[idx] = "[![image](" + file_info.DownloadURL + " \"" + prompt + "\")](" + file_info.DownloadURL + ")"
}

func Handler(c *gin.Context, response *http.Response, secret *tokens.Secret, proxy string, deviceId string, uuid string, original_request official_types.APIRequest) (string, *ContinueInfo) {
	max_tokens := false

	// Create a bufio.Reader from the response body
	reader := bufio.NewReader(response.Body)

	// Read the response byte by byte until a newline character is encountered
	if original_request.Stream {
		// Response content type is text/event-stream
		c.Header("Content-Type", "text/event-stream")
	} else {
		// Response content type is application/json
		c.Header("Content-Type", "application/json")
	}
	var finish_reason string
	var previous_text typings.StringStruct
	var original_response chatgpt_types.ChatGPTResponse
	var moderation_response chatgpt_types.ModerationResponse
	var isRole = true
	var imgSource []string
	var isEnd = false
	var convId string
	var msgId string

	for {
		var line string
		var err error
		line, err = reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", nil
		}
		if len(line) < 6 {
			continue
		}
		// Remove "data: " from the beginning of the line
		line = line[6:]
		// Check if line starts with [DONE]
		if !strings.HasPrefix(line, "[DONE]") {
			//moderation error
			_ = json.Unmarshal([]byte(line), &moderation_response)
			if moderation_response.Type == "moderation" && moderation_response.ModerationResponse.Blocked {
				log.Printf("Error in moderation")
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Error in moderation. The model produced invalid content. Consider modifying your prompt if you are seeing this error persistently.",
				})
				return "", nil
			}
			// Parse the line as JSON
			original_response.Message.ID = ""
			err = json.Unmarshal([]byte(line), &original_response)
			if err != nil {
				continue
			}
			if original_response.Error != nil {
				c.JSON(500, gin.H{"error": original_response.Error})
				return "", nil
			}
			if original_response.Message.ID == "" {
				continue
			}
			if original_response.ConversationID != convId {
				if convId == "" {
					convId = original_response.ConversationID
				} else {
					continue
				}
			}
			if !(original_response.Message.Author.Role == "assistant" || (original_response.Message.Author.Role == "tool" && original_response.Message.Content.ContentType != "text")) || original_response.Message.Content.Parts == nil {
				continue
			}
			if original_response.Message.Metadata.MessageType == "" || original_response.Message.Recipient != "all" {
				continue
			}
			if original_response.Message.Metadata.MessageType != "next" && original_response.Message.Metadata.MessageType != "continue" || !strings.HasSuffix(original_response.Message.Content.ContentType, "text") {
				continue
			}
			if original_response.Message.Content.ContentType == "text" && original_response.Message.ID != msgId {
				if msgId == "" && original_response.Message.Content.Parts[0].(string) == "" {
					msgId = original_response.Message.ID
				} else {
					continue
				}
			}
			if original_response.Message.EndTurn != nil && !original_response.Message.EndTurn.(bool) {
				msgId = ""
			}
			if len(original_response.Message.Metadata.Citations) != 0 {
				r := []rune(original_response.Message.Content.Parts[0].(string))
				offset := 0
				for _, citation := range original_response.Message.Metadata.Citations {
					rl := len(r)
					u, _ := url.Parse(citation.Metadata.URL)
					baseURL := u.Scheme + "://" + u.Host + "/"
					attr := urlAttrMap[baseURL]
					if attr == "" {
						attr = getURLAttribution(secret, deviceId, baseURL)
						if attr != "" {
							urlAttrMap[baseURL] = attr
						}
					}
					u.Fragment = ""
					original_response.Message.Content.Parts[0] = string(r[:citation.StartIx+offset]) + " ([" + attr + "](" + u.String() + " \"" + citation.Metadata.Title + "\"))" + string(r[citation.EndIx+offset:])
					r = []rune(original_response.Message.Content.Parts[0].(string))
					offset += len(r) - rl
				}
			}
			response_string := ""
			if original_response.Message.Content.ContentType == "multimodal_text" {
				apiUrl := "https://chatgpt.com/backend-api/files/"
				if FILES_REVERSE_PROXY != "" {
					apiUrl = FILES_REVERSE_PROXY
				}
				imgSource = make([]string, len(original_response.Message.Content.Parts))
				var wg sync.WaitGroup
				for index, part := range original_response.Message.Content.Parts {
					jsonItem, _ := json.Marshal(part)
					var dalle_content chatgpt_types.DalleContent
					err = json.Unmarshal(jsonItem, &dalle_content)
					if err != nil {
						continue
					}
					url := apiUrl + strings.Split(dalle_content.AssetPointer, "//")[1] + "/download"
					wg.Add(1)
					go GetImageSource(&wg, url, dalle_content.Metadata.Dalle.Prompt, secret, deviceId, index, imgSource)
				}
				wg.Wait()
				translated_response := official_types.NewChatCompletionChunk(strings.Join(imgSource, "") + "\n")
				if isRole {
					translated_response.Choices[0].Delta.Role = original_response.Message.Author.Role
				}
				response_string = "data: " + translated_response.String() + "\n\n"
			}
			if response_string == "" {
				response_string = chatgpt_response_converter.ConvertToString(&original_response, &previous_text, isRole)
			}
			if isRole && response_string != "" {
				isRole = false
			}

			if original_request.Stream {
				var isStop = false
				if !isRole {
					_, isStop = util.GetStopIndex(response_string, original_request.Stop)
				}
				if !isStop {
					_, err = c.Writer.WriteString(response_string)
					if err != nil {
						return "", nil
					}
					// Flush the response writer buffer to ensure that the client receives each line as it's written
					c.Writer.Flush()
				} else {
					isEnd = true
				}
			}
			isRole = false

			if original_response.Message.Metadata.FinishDetails != nil {
				if original_response.Message.Metadata.FinishDetails.Type == "max_tokens" {
					max_tokens = true
				}
				finish_reason = original_response.Message.Metadata.FinishDetails.Type
			}
			if isEnd {
				if original_request.Stream {
					final_line := official_types.StopChunk(finish_reason)
					c.Writer.WriteString("data: " + final_line.String() + "\n\n")
				}
				break
			}
		} else {
			if original_request.Stream {
				final_line := official_types.StopChunk(finish_reason)
				c.Writer.WriteString("data: " + final_line.String() + "\n\n")
			}
		}
	}
	respText := strings.Join(imgSource, "")
	if respText != "" {
		respText += "\n"
	}
	respText += previous_text.Text
	if !max_tokens {
		return respText, nil
	}
	return respText, &ContinueInfo{
		ConversationID: original_response.ConversationID,
		ParentID:       original_response.Message.ID,
	}
}

func HandlerTTS(response *http.Response, input string) (string, string) {
	// Create a bufio.Reader from the response body
	reader := bufio.NewReader(response.Body)

	var original_response chatgpt_types.ChatGPTResponse
	var convId string

	for {
		var line string
		var err error
		line, err = reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", ""
		}
		if len(line) < 6 {
			continue
		}
		// Remove "data: " from the beginning of the line
		line = line[6:]
		// Check if line starts with [DONE]
		if !strings.HasPrefix(line, "[DONE]") {
			// Parse the line as JSON
			original_response.Message.ID = ""
			err = json.Unmarshal([]byte(line), &original_response)
			if err != nil {
				continue
			}
			if original_response.Error != nil {
				return "", ""
			}
			if original_response.Message.ID == "" {
				continue
			}
			if original_response.ConversationID != convId {
				if convId == "" {
					convId = original_response.ConversationID
				} else {
					continue
				}
			}
			if original_response.Message.Author.Role == "assistant" && original_response.Message.Content.Parts[0].(string) == input {
				return original_response.Message.ID, convId
			}
		}
	}
	return "", ""
}

func GetTTS(secret *tokens.Secret, deviceId string, url string, proxy string) []byte {
	if proxy != "" {
		client.SetProxy(proxy)
	}
	request, err := newRequest(http.MethodGet, url, nil, secret, deviceId)
	if err != nil {
		return nil
	}
	response, err := client.Do(request)
	if err != nil {
		return nil
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil
	}
	blob, err := io.ReadAll(response.Body)
	if err != nil {
		return nil
	}
	return blob
}

func RemoveConversation(secret *tokens.Secret, deviceId string, id string, proxy string) {
	if proxy != "" {
		client.SetProxy(proxy)
	}
	url := "https://chatgpt.com/backend-api/conversation/" + id
	request, err := newRequest(http.MethodPatch, url, bytes.NewBuffer([]byte(`{"is_visible":false}`)), secret, deviceId)
	request.Header.Set("Content-Type", "application/json")
	if err != nil {
		return
	}
	response, err := client.Do(request)
	if err != nil {
		return
	}
	response.Body.Close()
}
