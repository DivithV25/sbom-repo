package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

var logger = logrus.New()

func main() {
	router := gin.Default()

	// Health check endpoint
	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "PRISM Scanner - Go App",
			"version": "1.0.0",
		})
	})

	// API endpoint
	router.GET("/api/data", func(c *gin.Context) {
		logger.Info("Fetching data...")
		c.JSON(http.StatusOK, gin.H{
			"status": "success",
			"data":   "sample data",
		})
	})

	logger.Info("Starting server on :8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
