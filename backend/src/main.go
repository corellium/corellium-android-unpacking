package main

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gitea.com/lunny/axmlParser"
	"github.com/bitly/go-nsq"
	"github.com/gin-gonic/gin"
)

func setupRouter() *gin.Engine {
	router := gin.Default()
	router.MaxMultipartMemory = 8 << 20

	router.GET("/health", func(context *gin.Context) {
		context.String(http.StatusOK, "OK")
	})

	//  curl -X POST 0.0.0.0:3000/unpack/APK_HASH --data-binary @APK_FILE
	router.POST("/unpack/:hash", func(context *gin.Context) {
		hash := context.Params.ByName("hash")
		if hash == "" {
			context.AbortWithError(http.StatusBadRequest,
				fmt.Errorf("No hash provided"))
			return
		}
		log.Printf("Got request for hash : %+v", hash)

		data, err := context.GetRawData()
		if err != nil {
			context.AbortWithError(http.StatusBadRequest,
				fmt.Errorf("Error with file : %+v", err))
			return
		}

		sha := sha1.Sum(data)
		shaString := fmt.Sprintf("%x", sha)
		log.Printf("Calculated sha %x", sha)
		if !strings.EqualFold(hash, shaString) {
			context.AbortWithError(http.StatusBadRequest,
				fmt.Errorf("Hashes didn't match : %s vs %s", hash, shaString))
			return
		}

		filepath := fmt.Sprintf("/data/apks/%s", shaString)
		if _, err = os.Stat(filepath); os.IsNotExist(err) {
			file, err := os.Create(filepath)
			if err != nil {
				context.AbortWithError(http.StatusBadRequest,
					fmt.Errorf("Error creating file on disk: %+v", err))
				return
			}
			defer file.Close()

			written, err := file.Write(data)
			if err != nil {
				context.AbortWithError(http.StatusBadRequest,
					fmt.Errorf("Error writing file to disk: %+v", err))
				return
			}
			log.Printf("Wrote %d bytes", written)
			file.Sync()
		}

		log.Printf("Wrote to disk : %s", filepath)

		_ = os.Mkdir(fmt.Sprintf("/data/assets/%s", shaString), 0777)

		axml := new(axmlParser.AppNameListener)
		_, err = axmlParser.ParseApk(filepath, axml)
		if err != nil {
			log.Panic("Error collecting apk package name")
			context.AbortWithError(http.StatusBadRequest,
				fmt.Errorf("Error collecting apk package name: %+v", err))
		}

		task := UnpackTask{
			Hash:        shaString,
			Filepath:    filepath,
			PackageName: axml.PackageName,
			ProxyPort:   adbProxyPort,
		}

		var taskData []byte
		taskData, err = json.Marshal(task)
		if err != nil {
			log.Panic("Error collecting apk package name")
			context.AbortWithError(http.StatusBadRequest,
				fmt.Errorf("Error creating task: %+v", err))
		}

		err = producer.Publish("unpack_tasks", taskData)
		if err != nil {
			log.Panic("Could not connect")
			context.AbortWithError(http.StatusBadRequest,
				fmt.Errorf("Error sending task: %+v", err))
		}

		context.JSON(http.StatusOK, gin.H{"hash": hash, "path": filepath})
	})

	//  curl 0.0.0.0:3000/unpack/APK_HASH/status
	router.GET("/unpack/:hash/status", func(context *gin.Context) {
		hash := context.Params.ByName("hash")
		if hash == "" {
			context.AbortWithError(http.StatusBadRequest,
				fmt.Errorf("No hash provided"))
			return
		}

		isSha, _ := regexp.MatchString(`\b[0-9a-f]{5,40}\b`, hash)
		if !isSha {
			context.AbortWithError(http.StatusBadRequest,
				fmt.Errorf("Bad hash provided"))
			return
		}

		log.Printf("Got status request for hash : %+v", hash)

		var files []string
		err := filepath.Walk(fmt.Sprintf("/data/assets/%s/", hash),
			func(path string, info os.FileInfo, err error) error {
				files = append(files, path)
				return nil
			})
		if err != nil {
			panic(err)
		}

		if len(files) < 1 {
			context.AbortWithError(http.StatusBadRequest,
				fmt.Errorf("No output for hash found"))
			return
		}

		context.JSON(http.StatusOK, gin.H{"hash": hash, "outputs": files})
	})

	//  curl 0.0.0.0:3000/unpack/APK_HASH/ASSET_HASH
	router.GET("/unpack/:hash/:asset", func(context *gin.Context) {
		hash := context.Params.ByName("hash")
		asset := context.Params.ByName("asset")
		if hash == "" || asset == "" {
			context.AbortWithError(http.StatusBadRequest,
				fmt.Errorf("No hash/asset provided"))
			return
		}

		isHashSha, _ := regexp.MatchString(`\b[0-9a-f]{5,40}\b`, hash)
		isAssetSha, _ := regexp.MatchString(`\b[0-9a-f]{5,40}\b`, asset)
		if !isHashSha || !isAssetSha {
			context.AbortWithError(http.StatusBadRequest,
				fmt.Errorf("Bad hash/asset provided"))
			return
		}

		log.Printf("Got status request for hash : %+v's asset of : %+v", hash, asset)

		file := fmt.Sprintf("/data/assets/%s/%s", hash, asset)
		if _, err := os.Stat(file); os.IsNotExist(err) {
			context.AbortWithError(http.StatusBadRequest,
				fmt.Errorf("Unable to locate asset"))
			return
		}

		context.Header("Content-Description", "File Transfer")
		context.Header("Content-Transfer-Encoding", "binary")
		context.Header("Content-Disposition", "attachment; filename="+file)
		context.Header("Content-Type", "application/octet-stream")
		context.File(file)
	})

	return router
}

func initialize() {
	_ = os.Mkdir("/data/apks", 0777)
	_ = os.Mkdir("/data/assets", 0777)
}

var (
	producer     *nsq.Producer
	adbProxyPort int
)

func main() {
	initialize()

	servePort, err := strconv.Atoi(os.Getenv("SERVE_PORT"))
	if err != nil {
		panic(fmt.Sprintf("Failed to get serve port variable SERVE_PORT : %+v", err))
	}

	adbProxyPort, err = strconv.Atoi(os.Getenv("ADB_PROXY"))
	if err != nil {
		panic(fmt.Sprintf("Failed to get adb proxy port variable ADB_PROXY : %+v", err))
	}

	instanceID := os.Getenv("INSTANCE_ID")
	if instanceID == "" {
		panic(fmt.Sprintf("Failed to get vm instance id variable INSTANCE_ID : %+v", instanceID))
	}

	apiURL := os.Getenv("CORELLIUM_URL")
	if apiURL == "" {
		panic(fmt.Sprintf("Failed to get corellium base url variable CORELLIUM_URL : %+v", apiURL))
	}

	user := os.Getenv("CORELLIUM_USERNAME")
	if user == "" {
		panic(fmt.Sprintf("Failed to get corellium username variable CORELLIUM_USERNAME : %+v", user))
	}

	pass := os.Getenv("CORELLIUM_PASSWORD")
	if pass == "" {
		panic(fmt.Sprintf("Failed to get corellium password variable CORELLIUM_PASSWORD : %+v", pass))
	}

	corellium := Corellium{
		username: user,
		password: pass,
		domain:   apiURL,
	}

	_, err = corellium.Login()
	if err != nil {
		log.Panicf("Unable to login : %+v", err)
	}

	instances, err := corellium.Instances()
	if err != nil {
		log.Panicf("Unable to get instances : %+v", err)
	}

	// Find adb port
	remoteHost := ""
	remotePort := ""
	for _, instance := range instances.Instances {
		if instance.ID == instanceID {
			log.Printf("Found matching instance ID: %+v", instance)

			remoteHost = instance.ServicesIP
			remotePort = instance.PortADB

			if instance.Status != "ACTIVE" {
				log.Fatalf("Instance may not be ACTIVE, currently set to %s", instance.Status)
			}
		}
	}

	if remoteHost == "" || remotePort == "" {
		panic("Unable to find instance data, failing...")
	}

	for {
		timeout := time.Duration(60 * time.Second)
		_, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%s", remoteHost, remotePort), timeout)
		if err != nil {
			log.Println("Adb host unreachable, retrying in 5 seconds, error : ", err)
			time.Sleep(5 * time.Second)
		} else {
			log.Println("Adb host was reachable, continuing...")
			break
		}
	}

	// Connect to adb port via proxy
	port, err := proxy(fmt.Sprintf("%s:%s", remoteHost, remotePort), adbProxyPort)
	if err != nil {
		panic(fmt.Sprintf("Error setting up adb proxy : %+v", err))
	}
	log.Printf("ADB Proxy opened on %d for %s:%s", port, remoteHost, remotePort)

	// Set up nsq
	config := nsq.NewConfig()
	producer, _ = nsq.NewProducer("nsqd:4150", config)
	defer producer.Stop()

	rand.Seed(time.Now().UnixNano())
	router := setupRouter()

	router.Run(fmt.Sprintf(":%d", servePort))

	log.Printf("[unpacker-api] Serving on :%d", servePort)
}
