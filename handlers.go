package main

import (
	"encoding/json"
	chatgpt_request_converter "freechatgpt/conversion/requests/chatgpt"
	chatgpt "freechatgpt/internal/chatgpt"
	"freechatgpt/internal/proxys"
	"freechatgpt/internal/tokens"
	official_types "freechatgpt/typings/official"
	"io"
	"log"
	"os"
	"strings"

	http "github.com/bogdanfinn/fhttp"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	arkose "github.com/xqdoo00o/funcaptcha"
)

var (
	uuidNamespace = uuid.MustParse("12345678-1234-5678-1234-567812345678")
)

func passwordHandler(c *gin.Context) {
	// Get the password from the request (json) and update the password
	type password_struct struct {
		Password string `json:"password"`
	}
	var password password_struct
	err := c.BindJSON(&password)
	if err != nil {
		c.String(400, "password not provided")
		return
	}
	ADMIN_PASSWORD = password.Password
	// Set environment variable
	os.Setenv("ADMIN_PASSWORD", ADMIN_PASSWORD)
	c.String(200, "password updated")
}

func tokensHandler(c *gin.Context) {
	// Get the request_tokens from the request (json) and update the request_tokens
	var request_tokens map[string]tokens.Secret
	err := c.BindJSON(&request_tokens)
	if err != nil {
		c.String(400, "tokens not provided")
		return
	}
	ACCESS_TOKENS = tokens.NewAccessToken(request_tokens)
	ACCESS_TOKENS.Save()
	validAccounts = ACCESS_TOKENS.GetKeys()
	c.String(200, "tokens updated")
}
func optionsHandler(c *gin.Context) {
	// Set headers for CORS
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Methods", "POST")
	c.Header("Access-Control-Allow-Headers", "*")
	c.JSON(200, gin.H{
		"message": "pong",
	})
}

func simulateModel(c *gin.Context) {
	c.JSON(200, gin.H{
		"object": "list",
		"data": []gin.H{
			{
				"id":       "gpt-3.5-turbo",
				"object":   "model",
				"created":  1688888888,
				"owned_by": "chatgpt-to-api",
			},
			{
				"id":       "gpt-4",
				"object":   "model",
				"created":  1688888888,
				"owned_by": "chatgpt-to-api",
			},
		},
	})
}

func generateUUID(name string) string {
	return uuid.NewSHA1(uuidNamespace, []byte(name)).String()
}
func nightmare(c *gin.Context) {
	var original_request official_types.APIRequest
	err := c.BindJSON(&original_request)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{
			"message": "Request must be proper JSON",
			"type":    "invalid_request_error",
			"param":   nil,
			"code":    err.Error(),
		}})
		return
	}
	var isPrompt = false
	if strings.HasPrefix(c.Request.URL.Path, "/v1/chat/completions") {
		if original_request.Messages == nil || len(original_request.Messages) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{
				"message": "field messages is required",
				"type":    "invalid_request_error",
				"param":   nil,
				"code":    "required_field_missing",
			}})
			return
		}
		isPrompt = false
	} else if strings.HasPrefix(c.Request.URL.Path, "/v1/completions") {
		if original_request.Prompt == nil || original_request.Prompt == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{
				"message": "field prompt is required",
				"type":    "invalid_request_error",
				"param":   nil,
				"code":    "required_field_missing",
			}})
			return
		}
		var strArr []string
		if str, ok := original_request.Prompt.(string); !ok {
			if ints, ok := original_request.Prompt.([]interface{}); !ok {
				if strs, ok := original_request.Prompt.([]string); ok {
					strArr = append(strArr, strs...)
				}
			} else {
				for _, item := range ints {
					if str, ok := item.(string); ok {
						strArr = append(strArr, str)
					}
				}
			}
		} else {
			strArr = append(strArr, str)
		}
		if len(strArr) <= 0 {
			log.Printf("original_request.Prompt.(string|interface|strings)-Error: %v", original_request.Prompt)
			c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{
				"message": "field prompt is a wrong type",
				"type":    "invalid_request_error",
				"param":   nil,
				"code":    "required_field_error",
			}})
			return
		}
		for _, item := range strArr {
			newMsg := official_types.APIMessage{
				Role:    "user",
				Content: item,
			}
			original_request.Messages = append(original_request.Messages, newMsg)
		}
		isPrompt = true
	}

	account, secret := getSecret()
	var proxy_url = proxys.GetProxyIP()

	uid := uuid.NewString()
	var deviceId string
	if account == "" {
		deviceId = uid
		chatgpt.SetOAICookie(deviceId)
	} else {
		deviceId = generateUUID(account)
		chatgpt.SetOAICookie(deviceId)
	}
	chat_require := chatgpt.CheckRequire(&secret, deviceId, proxy_url)
	if chat_require == nil {
		c.JSON(500, gin.H{"error": "Oops!! Failed to create completion as the model generated invalid Unicode output. Unfortunately, this can happen in rare situations. Consider reviewing your prompt or reducing the temperature of your request. You can retry your request, or contact us through our help center at	help.openai.com if the error persists."})
		return
	}
	var proofToken string
	if chat_require.Proof.Required {
		proofToken = chatgpt.CalcProofToken("gAAAAAB", chat_require.Proof.Seed, chat_require.Proof.Difficulty)
	}
	var arkoseToken string
	if chat_require.Arkose.Required {
		arkoseToken, err = arkose.GetOpenAIToken(4, secret.PUID, chat_require.Arkose.DX, proxy_url)
		if err != nil {
			println("Error getting Arkose token: ", err)
		}
	}
	// Convert the chat request to a ChatGPT request
	translated_request := chatgpt_request_converter.ConvertAPIRequest(original_request, account, &secret, deviceId, proxy_url)

	retryNeeded := true
	retryCount := 1
	var response *http.Response
	var resErr error
	var bodyBytes []byte

	for retryNeeded && retryCount < chatgpt.RetryTimes {
		response, resErr = chatgpt.POSTconversation(translated_request, &secret, deviceId, chat_require.Token, arkoseToken, proofToken, proxy_url)
		if resErr != nil && !chatgpt.IsRetryError(resErr.Error()) {
			log.Printf("POSTconversation-Error: %s", resErr)
			break
		}
		if response != nil && (response.StatusCode == http.StatusRequestEntityTooLarge ||
			response.StatusCode == http.StatusUnauthorized ||
			response.StatusCode == http.StatusInternalServerError ||
			response.StatusCode == http.StatusGatewayTimeout ||
			response.StatusCode == 524 ||
			response.StatusCode == http.StatusServiceUnavailable ||
			response.StatusCode == http.StatusForbidden) {

			bodyBytes, _ = io.ReadAll(response.Body)
			var error_response map[string]interface{}
			err := json.Unmarshal(bodyBytes, &error_response)
			if err == nil && error_response["detail"] != "" && response.StatusCode == http.StatusInternalServerError {
				//500错误, 且存在错误, 无需重试, 直接返回错误
				log.Printf("conversation异常: %s, %s", response.Status, error_response["detail"])
				break
			}
			//413问题处理
			if response != nil && response.StatusCode == http.StatusRequestEntityTooLarge {
				if len(original_request.Messages) <= 2 {
					//上下文已经小于2, 不需要切了, 直接更改状态为413,准备发起重试
					response.StatusCode = http.StatusRequestEntityTooLarge
					resErr = nil
					break
				}
				if len(original_request.Messages) > 20 {
					//减少内部循环
					original_request.Messages = original_request.Messages[:20]
				}
				if len(original_request.Messages) > 2 {
					original_request.Messages = original_request.Messages[2:]
				}
			}
			retryCount++
			//回收当次资源
			response.Body.Close()
		} else {
			retryNeeded = false
		}
	}
	if resErr != nil {
		c.JSON(500, gin.H{
			"error": "Oops!! Failed to create completion as the model generated invalid Unicode output. Unfortunately, this can happen in rare situations. Consider reviewing your prompt or reducing the temperature of your request. You can retry your request, or contact us through our help center at	help.openai.com if the error persists.",
		})
		return
	}

	defer response.Body.Close()
	if chatgpt.Handle_request_error(c, response, bodyBytes) {
		return
	}
	var full_response string
	for i := 3; i > 0; i-- {
		var continue_info *chatgpt.ContinueInfo
		var response_part string
		response_part, continue_info = chatgpt.Handler(c, response, &secret, proxy_url, deviceId, uid, original_request)
		full_response += response_part
		if continue_info == nil {
			break
		}
		println("Continuing conversation")
		translated_request.Messages = nil
		translated_request.Action = "continue"
		translated_request.ConversationID = continue_info.ConversationID
		translated_request.ParentMessageID = continue_info.ParentID
		chat_require = chatgpt.CheckRequire(&secret, deviceId, proxy_url)
		if chat_require.Proof.Required {
			proofToken = chatgpt.CalcProofToken("gAAAAAB", chat_require.Proof.Seed, chat_require.Proof.Difficulty)
		}
		if chat_require.Arkose.Required {
			arkoseToken, err = arkose.GetOpenAIToken(4, secret.PUID, chat_require.Arkose.DX, proxy_url)
			if err != nil {
				println("Error getting Arkose token: ", err)
			}
		}
		response, err = chatgpt.POSTconversation(translated_request, &secret, deviceId, chat_require.Token, arkoseToken, proofToken, proxy_url)
		if err != nil {
			c.JSON(500, gin.H{
				"error": "error sending request",
			})
			return
		}
		bodyBytes, _ = io.ReadAll(response.Body)
		defer response.Body.Close()
		if chatgpt.Handle_request_error(c, response, bodyBytes) {
			return
		}
	}
	if c.Writer.Status() != 200 {
		return
	}
	if !original_request.Stream {
		c.JSON(200, official_types.NewChatCompletion(full_response, isPrompt, original_request.Stop))
	} else {
		c.String(200, "data: [DONE]\n\n")
	}
}

var ttsFmtMap = map[string]string{
	"mp3":  "mp3",
	"opus": "opus",
	"aac":  "aac",
	"flac": "aac",
	"wav":  "aac",
	"pcm":  "aac",
}

var ttsTypeMap = map[string]string{
	"mp3":  "audio/mpeg",
	"opus": "audio/ogg",
	"aac":  "audio/aac",
}

var ttsVoiceMap = map[string]string{
	"alloy":   "cove",
	"echo":    "ember",
	"fable":   "breeze",
	"onyx":    "cove",
	"nova":    "juniper",
	"shimmer": "juniper",
}

func tts(c *gin.Context) {
	var original_request official_types.TTSAPIRequest
	err := c.BindJSON(&original_request)
	if err != nil {
		c.JSON(400, gin.H{"error": gin.H{
			"message": "Request must be proper JSON",
			"type":    "invalid_request_error",
			"param":   nil,
			"code":    err.Error(),
		}})
		return
	}

	account, secret := getSecret()
	if account == "" || secret.PUID == "" {
		c.JSON(500, gin.H{"error": "Plus user only"})
		return
	}
	proxy_url := proxys.GetProxyIP()
	var deviceId = generateUUID(account)
	chatgpt.SetOAICookie(deviceId)
	chat_require := chatgpt.CheckRequire(&secret, deviceId, proxy_url)
	if chat_require == nil {
		c.JSON(500, gin.H{"error": "unable to check chat requirement"})
		return
	}
	var proofToken string
	if chat_require.Proof.Required {
		proofToken = chatgpt.CalcProofToken("gAAAAAB", chat_require.Proof.Seed, chat_require.Proof.Difficulty)
	}
	var arkoseToken string
	if chat_require.Arkose.Required {
		arkoseToken, err = arkose.GetOpenAIToken(4, secret.PUID, chat_require.Arkose.DX, proxy_url)
		if err != nil {
			println("Error getting Arkose token: ", err)
		}
	}
	// Convert the chat request to a ChatGPT request
	translated_request := chatgpt_request_converter.ConvertTTSAPIRequest(original_request.Input)

	response, err := chatgpt.POSTconversation(translated_request, &secret, deviceId, chat_require.Token, arkoseToken, proofToken, proxy_url)
	if err != nil {
		c.JSON(500, gin.H{"error": "error sending request"})
		return
	}
	defer response.Body.Close()

	bodyBytes, _ := io.ReadAll(response.Body)
	if chatgpt.Handle_request_error(c, response, bodyBytes) {
		return
	}
	msgId, convId := chatgpt.HandlerTTS(response, original_request.Input)
	format := ttsFmtMap[original_request.Format]
	if format == "" {
		format = "aac"
	}
	voice := ttsVoiceMap[original_request.Voice]
	if voice == "" {
		voice = "cove"
	}
	apiUrl := "https://chatgpt.com/backend-api/synthesize?message_id=" + msgId + "&conversation_id=" + convId + "&voice=" + voice + "&format=" + format
	data := chatgpt.GetTTS(&secret, deviceId, apiUrl, proxy_url)
	if data != nil {
		c.Data(200, ttsTypeMap[format], data)
	} else {
		c.JSON(500, gin.H{"error": "synthesize error"})
	}
	chatgpt.RemoveConversation(&secret, deviceId, convId, proxy_url)
}
