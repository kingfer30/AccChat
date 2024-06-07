package main

import (
	"freechatgpt/initialize"
	"freechatgpt/internal/chatgpt"
	"freechatgpt/internal/tokens"
	"freechatgpt/middlewares"
	"freechatgpt/util"
	"log"
	"os"

	chatgpt_types "freechatgpt/typings/chatgpt"

	"github.com/acheong08/endless"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

var HOST string
var PORT string
var ACCESS_TOKENS tokens.AccessToken

func init() {
	_ = godotenv.Load(".env")

	HOST = os.Getenv("SERVER_HOST")
	PORT = os.Getenv("SERVER_PORT")
	if HOST == "" {
		HOST = "0.0.0.0"
	}
	if PORT == "" {
		PORT = "8080"
	}
	initialize.InitProxy()
	readAccounts()
	scheduleTokenPUID()
	err := util.InitRedisClient()
	if err != nil {
		log.Println("failed to initialize Redis: " + err.Error())
	}
	go chatgpt.InitScriptDpl()
}
func main() {
	gin.SetMode(gin.ReleaseMode)
	defer chatgpt_types.SaveFileHash()
	router := gin.Default()

	router.Use(cors)
	router.Use(gin.Recovery())

	router.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	admin_routes := router.Group("/admin")
	admin_routes.Use(adminCheck)

	/// Admin routes
	admin_routes.PATCH("/password", passwordHandler)
	admin_routes.PATCH("/tokens", tokensHandler)
	/// Public routes
	router.OPTIONS("/v1/chat/completions", optionsHandler)
	router.OPTIONS("/v1/audio/speech", optionsHandler)
	router.OPTIONS("/v1/models", optionsHandler)

	authGroup := router.Group("").Use(middlewares.Authorization)
	authGroup.POST("/v1/chat/completions", nightmare)
	authGroup.POST("/v1/completions", nightmare)
	authGroup.GET("/v1/models", simulateModel)
	authGroup.POST("/v1/audio/speech", Authorization, tts)
	endless.ListenAndServe(HOST+":"+PORT, router)
}
