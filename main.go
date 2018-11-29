package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"fmt"
	"go-fullAuth-jwt-sengrid/sendmail"
	"os"
	"strconv"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/mitchellh/mapstructure"
	logging "github.com/op/go-logging"
	sendgrid "github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var err error

var (
	configSendGrid             string
	configSendGridAddress      string
	configmysqluserpw          string
	configserverport           string
	configRedisCacheserver     string
	configRedisCacheaccountsDB int
)

var secret = []byte("secrety")
var log = logging.MustGetLogger("iotmeta")
var format = logging.MustStringFormatter(
	`%{color}%{shortfunc} ▶ %{level:.4s} %{color:reset} %{message}`,
)

func main() {

	initiateLogger()

	configSendGrid = viper.GetString("SendGrid.SENDGRID_API_KEY")
	configSendGridAddress = viper.GetString("SendGrid.Address")
	configmysqluserpw = viper.GetString("mysql.userpw")
	configserverport = viper.GetString("server.port")
	configRedisCacheserver = viper.GetString("RedisCache.server")
	configRedisCacheaccountsDB = viper.GetInt("RedisCache.accountsDB")
	router := gin.Default()
	store, _ := sessions.NewRedisStore(configRedisCacheaccountsDB, "tcp", configRedisCacheserver, "", []byte("secret"))
	store.Options(sessions.Options{MaxAge: 3600})
	router.Use(sessions.Sessions("mysession", store))
	router.POST("/signup", signup)
	router.POST("/login", login)
	router.POST("/reset", reset)
	router.POST("/forgetpassword", forgetpassword)
	router.POST("/usercreate", usercreate)
	router.GET("/verifyforgetpw/:tokenString", verifyforgetpw)
	router.GET("/routes/:tokenString/:email", routes)
	router.GET("/userverify/:tokenString/:permission_id", userverify)
	router.DELETE("/deleteuser", deleteuser)
	router.GET("/logout", logout)
	router.Run(configserverport)

}
func initiateLogger() {
	viper.SetConfigName("global")
	viper.AddConfigPath("./")
	f, _ := os.OpenFile("access.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	configError := viper.ReadInConfig()
	backend := logging.NewLogBackend(f, "", 0)
	backendFormatter := logging.NewBackendFormatter(backend, format)
	backendLeveled := logging.AddModuleLevel(backend)
	fmt.Println("Log level : ", logging.GetLevel("iotserver"))
	logging.SetBackend(backendLeveled, backendFormatter)
	if configError != nil {
		log.Errorf("Fatal error config file: %s \n", configError)
		panic("Fatal error")
	}
}

//Connection to mysql Db
func dbConn() (db *sql.DB) {
	db, err := sql.Open("mysql", configmysqluserpw)
	if err != nil {
		panic(err.Error())
	}
	return db
}

//User and Admin login, User/Admin should provide username and password
func login(c *gin.Context) {

	db := dbConn()
	var (
		username string
		password string
	)
	session := sessions.Default(c)
	username = c.PostForm("username")
	password = c.PostForm("password")

	//md5 password hashing
	hasher := md5.New()
	hasher.Write([]byte(password))
	hash := hex.EncodeToString(hasher.Sum(nil))
	fmt.Println(username)
	err = db.QueryRow("SELECT username, password FROM auth WHERE username=? and password=?", username, hash).Scan(&username, &password)

	if err == nil {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": username,
			"exp":      time.Now().Add(time.Hour * 24).Unix(),
		})
		tokenString, _ := token.SignedString(secret)
		fmt.Println(tokenString)

		if len(tokenString) >= 1 {
			session.Set("username", username)
			_ = session.Save()
			c.JSON(200, gin.H{"message": "Successfully authenticated user",
				"username": username,
			})
			log.Debug("Successfully authenticated user ", username)
		}
	} else {
		c.JSON(400, gin.H{"message": "username or password is wrong ",
			"username": username,
		})
		log.Error("wrong username and password")
	}
}

func logout(c *gin.Context) {
	session := sessions.Default(c)
	username := session.Get("username")
	if username == nil {
		c.JSON(400, gin.H{"error": "Invalid session token",
			"username": username,
		})
		log.Debug("Invalid session")
	} else {
		fmt.Println(username)
		session.Delete("username")
		session.Save()
		c.JSON(200, gin.H{"message": "Successfully logged out",
			"username": username,
		})
		log.Debug("Succesfully logged out", username)
	}
}

func reset(c *gin.Context) {

	db := dbConn()
	var (
		username string
		password string
	)
	username = c.PostForm("username")
	password = c.PostForm("password")
	userModified := time.Now().UTC()
	err = db.QueryRow("SELECT username from auth_user where username=? ", username).Scan(&username)
	if err == nil {
		fmt.Println("username is available")
		hasher := md5.New()
		hasher.Write([]byte(password))
		hash := hex.EncodeToString(hasher.Sum(nil))
		out, err := db.Prepare("UPDATE auth_user SET password=?, last_modified=? WHERE username=?")
		out.Exec(hash, userModified, username)
		c.JSON(200, gin.H{"message": "password updated successfully"})
		if err != nil {
			log.Error("cannot update the password", username)
			c.JSON(400, gin.H{"message": "cannot update the password",
				"username": username,
			})

		}
	} else {
		log.Error("username is not available", username)
		c.JSON(400, gin.H{"message": "username is not available ",
			"username": username,
		})
	}
}

func forgetpassword(c *gin.Context) {

	db := dbConn()
	var (
		username string
		email    string
	)
	username = c.PostForm("username")

	email = c.PostForm("email")

	err := db.QueryRow("SELECT username, email FROM auth_user WHERE username=? and email=?", username, email).Scan(&username, &email)
	if err == nil {

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": username,
			"email":    email,
			"exp":      time.Now().Add(time.Hour * 24).Unix(),
		})
		tokenString, _ := token.SignedString([]byte("secret"))

		fmt.Println(tokenString)
		from := mail.NewEmail("noreply@smartron.com", configSendGridAddress)
		subject := ("Click the link to authenticate user ")
		to := mail.NewEmail("", email)
		plainTextContent := "hello"
		htmlContent := "http://localhost:8080/verifyforgetpw" + "/" + tokenString
		message := mail.NewSingleEmail(from, subject, to, plainTextContent, htmlContent)
		client := sendgrid.NewSendClient(configSendGrid)
		response, err := client.Send(message)
		fmt.Println(response)
		if err != nil {
			log.Error("Internal error cannot able to send the mail", username)
			c.JSON(400, gin.H{"message": "Internal error cannot able to send the mail",
				"username": username,
			})
		}
		log.Debug("verify link in email to reset password", username)
		c.JSON(200, gin.H{"message": "verify link in email to reset password",
			"username": username,
		})

	}
}

// Verify for verify forget password with username and email
// type Verify struct {
// 	username string `json:"username"`
// 	email    string `json:"email"`
// }

func verifyforgetpw(c *gin.Context) {

	var (
		tokenString string
	)
	tokenString = c.Params.ByName("tokenString")
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return []byte("secret"), nil
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		var user User
		mapstructure.Decode(claims, &user)
		fmt.Println(claims["username"], claims["email"])
		var a interface{} = claims["username"]
		username := a.(string)
		var i interface{} = claims["email"]
		email := i.(string)
		log.Debug("verify success", username)
		c.JSON(200, gin.H{"message": "verify success",
			"username": username,
			"email":    email,
		})

	} else {
		log.Error("Invalid token")
		c.JSON(400, gin.H{"message": "Invalid token"})
	}
}

func signup(c *gin.Context) {

	db := dbConn()
	var (
		username string
		email    string
		password string
		// tokenString string
	)
	username = c.PostForm("username")
	email = c.PostForm("email")
	password = c.PostForm("password")

	if username == "" || email == "" || password == "" {
		log.Error("Empty String")
		fmt.Println("emptystring")
		c.JSON(400, gin.H{"message": "empty string"})
		return
	}
	row := db.QueryRow("SELECT username FROM auth WHERE username=? ", username)
	err = row.Scan(&username)
	if err == nil {
		log.Error("username is already exists")
		c.JSON(400, gin.H{"message": "Username is already exists",
			"username": username,
		})
		return
	}
	row = db.QueryRow("SELECT email FROM auth WHERE email=? ", email)
	err = row.Scan(&email)

	if err != nil {
		tokenString, err := authorize(username, password)

		a := sendmail.SendMail(username, tokenString, email)
		fmt.Println(a)
		if err != nil {
			fmt.Println("err")
		}
		log.Debug("signup success  confirm link in mail id")
		c.JSON(200, gin.H{"message": "signup success  confirm link in mail id",
			"username": username,
			"password": password,
			"email":    email,
		})

	} else {
		log.Error("organization is already exists")
		c.JSON(400, gin.H{"message": "username is already exists",
			"username": username,
		})
	}

}

func authorize(username string, password string) (token string, autherr error) {
	_, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err == nil {

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": username,
			"password": password,
			"exp":      time.Now().Add(time.Hour * 24).Unix(),
		})
		tokenString, _ := token.SignedString([]byte("secret"))
		fmt.Println(tokenString)
		return tokenString, nil

	} else {

		autherr = fmt.Errorf("Cannot authorize %q", username)

		return token, autherr
	}

}

// type User struct {
// 	username string `json:"username"`
// 	password string `json:"password"`
// }

func routes(c *gin.Context) {

	db := dbConn()
	var (
		email       string
		tokenString string
	)
	tokenString = c.Params.ByName("tokenString")
	email = c.Params.ByName("email")

	userCreated := time.Now().UTC()
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return []byte("secret"), nil
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		var user User
		mapstructure.Decode(claims, &user)
		fmt.Println(claims["username"], claims["password"])
		var a interface{} = claims["username"]
		username := a.(string)
		fmt.Println(username)
		var i interface{} = claims["password"]
		password := i.(string)
		fmt.Println(password)
		hasher := md5.New()
		hasher.Write([]byte(password))
		hash := hex.EncodeToString(hasher.Sum(nil))
		fmt.Println(username)

		_, err = db.Exec("INSERT INTO auth(username, email, password, user_created) VALUES( ?, ?, ?, ?)", &username, &email, &hash, &userCreated)
		if err != nil {
			log.Error("Unable to create an account", username)
			c.JSON(400, gin.H{"message": "Unable to create an account",
				"username":     username,
				"email":        email,
				"password":     hash,
				"user_created": userCreated,
			})
			fmt.Println("err insert")

		} else {
			// err = db.QueryRow("SELECT id, username FROM auth WHERE username=?", username).Scan(&id, &username)
			// _, err = db.Exec("INSERT INTO auth_access (auth_role_id, permission_id, user_id) VALUES(?,?,?)", &role, &permission, &id)
			log.Debug("user is verified and permission is given", username)
			c.JSON(200, gin.H{"message": "user is created and verified ",
				"username":     username,
				"email":        email,
				"password":     hash,
				"user_created": userCreated,
			})
		}
	}
}

//admin can able to create a user in this api username, email,org, dummy pw and permissionp_id are the inputs
// user will get the email with the token verification once the user clicks the token he will be redirect to the reset api
//where he can able to reset the password
func usercreate(c *gin.Context) {

	db := dbConn()

	var (
		username     string
		email        string
		organization string
		password     string
		role         int
	)
	username = c.PostForm("username")
	organization = c.PostForm("organization")
	email = c.PostForm("email")
	permission_id := c.PostForm("permission_id")
	password = c.PostForm("password")

	userCreated := time.Now().UTC()
	role = 2

	if username == "" || organization == "" || email == "" || password == "" {
		log.Error("Empty String")
		c.JSON(400, gin.H{"message": "empty string"})
		return
	}

	hasher := md5.New()
	hasher.Write([]byte(password))
	hash := hex.EncodeToString(hasher.Sum(nil))
	row := db.QueryRow("SELECT username FROM auth_user WHERE username=?", username)
	err = row.Scan(&username)

	if err != nil {

		_, err = db.Exec("INSERT INTO auth_user(organization, username, email, password, role, user_created) VALUES( ?, ?, ?, ?, ?, ?)", &organization, &username, &email, &hash, &role, &userCreated)

		if err != nil {
			log.Error("Unable to insert new user into auth_user", username)
			c.JSON(400, gin.H{"message": "Unalbe to insert new user into auth_user table",
				"username": username,
				"email":    email,
			})
		}
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username":      username,
		"email":         email,
		"permission_id": permission_id,
		"exp":           time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, _ := token.SignedString([]byte("secret"))

	fmt.Println(tokenString)
	from := mail.NewEmail("noreply@smartron.com", configSendGridAddress)
	subject := ("Click the link to authenticate user ")
	to := mail.NewEmail("", email)
	plainTextContent := "hello"
	htmlContent := "http://localhost:8080/userverify" + "/" + tokenString + "/" + permission_id
	message := mail.NewSingleEmail(from, subject, to, plainTextContent, htmlContent)
	client := sendgrid.NewSendClient(configSendGrid)
	response, err := client.Send(message)
	fmt.Println(response)

	if err != nil {
		log.Error("Internal error cannot able to send the mail", username)
		c.JSON(400, gin.H{"message": "Internal error cannot able to send the mail",
			"username": username,
		})
	}
	log.Debug("email sent to the user", username)
	c.JSON(200, gin.H{"message": "verify link in email to reset password",
		"username": username,
	})
}

type User struct {
	username      string `json:"username"`
	password      string `json:"password"`
	email         string `json:"email"`
	permission_id string `json:"permission_id"`
}

//This is the get api for the usercreation.
func userverify(c *gin.Context) {

	db := dbConn()

	var (
		tokenString  string
		permissionId string
		role         int
		id           int
	)
	tokenString = c.Params.ByName("tokenString")
	role = 2

	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return []byte("secret"), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		var user User
		mapstructure.Decode(claims, &user)
		fmt.Println(claims["username"], claims["email"], claims["permission_id"])
		var a interface{} = claims["username"]
		username := a.(string)
		var i interface{} = claims["email"]
		email := i.(string)
		var p interface{} = claims["permission_id"]
		permissionId = p.(string)

		log.Debug("Verify success", username)
		c.JSON(200, gin.H{"message": "verify success",
			"username":      username,
			"email":         email,
			"permission_id": permissionId,
		})

		permission, err := strconv.Atoi(permissionId)

		err = db.QueryRow("SELECT id, username FROM auth_user WHERE username=?", username).Scan(&id, &username)

		if err == nil {
			_, err = db.Exec("INSERT INTO auth_access (auth_role_id, permission_id, user_id) VALUES(?,?,?)", &role, &permission, &id)
			log.Debug("Permission access is given to the user", username)
			c.JSON(200, gin.H{"message": "permission is given for the user",
				"username": username,
				"id":       id,
			})
		}

	} else {
		c.JSON(400, gin.H{"message": "Invalid token"})
		log.Error("Invalid token")
	}
}

//Delete the user with  required username, so it will delete the permission and proceed with deleting the user in auth_user table
func deleteuser(c *gin.Context) {

	db := dbConn()

	var (
		username string
		id       int
	)
	username = c.PostForm("username")

	err = db.QueryRow("SELECT id, username FROM auth_user WHERE username=?", username).Scan(&id, &username)

	if err == nil {

		_, _ = db.Exec("DELETE FROM auth_access WHERE user_id=?", &id)

		delete, err := db.Prepare("DELETE FROM auth_user WHERE id=?")
		delete.Exec(id)
		log.Debug("User is deleted from user table and access table", username)
		c.JSON(200, gin.H{"message": "User is deleted from user table and access table",
			"username": username,
			"id":       id,
		})

		if err != nil {
			log.Error("Cannot able to delete the parent row", username)
			c.JSON(400, gin.H{"message": "Cannot able to delete the parent row",
				"username": username,
				"id":       id,
			})
		}

	} else {
		log.Error("Username is not available in user table", username)
		c.JSON(400, gin.H{"message": "Username is not available in user table",
			"username": username,
			"id":       id,
		})
	}

}
