package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

type SignUpReq struct {
	Name       string `json:"name"`
	Password   string `json:"password"`
	Public_key string `json:"public_key"`
}

type SignInReq struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type SignInResp struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
}

type Response struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type SendMessageReq struct {
	ToUserID int    `json:"toUserId"`
	Text     string `json:"text"`
}

type MessageResp struct {
	ID      int    `json:"id"`
	From    string `json:"from"`
	To      string `json:"to"`
	Text    string `json:"text"`
	Created string `json:"created"`
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func generateToken(userID int, username string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"name":    username,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	secret_key := os.Getenv("JWT_SECRET")
	if secret_key == "" {
		secret_key = "defoultKey"
	}

	return token.SignedString([]byte(secret_key))
}

func checkToken(TokenS string) (int, string, error) {
	secret := os.Getenv("JWT_SECRET")

	if secret == "" {
		secret = "defoultKey"
	}

	token, err := jwt.Parse(TokenS, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	if err != nil {
		return 0, "", err
	}

	claims := token.Claims.(jwt.MapClaims)
	userID := int(claims["user_id"].(float64))
	username := claims["name"].(string)

	return userID, username, nil
}

func LoadDB() *pgxpool.Pool {
	err := godotenv.Load()
	if err != nil {
		err = godotenv.Load()
		if err != nil {
			log.Fatal(".env file not found")
			return nil
		}
	}

	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")

	if dbHost == "" || dbPort == "" || dbUser == "" || dbPassword == "" || dbName == "" {
		log.Fatal("Missing DB credentials in .env file")
		return nil
	}

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		dbUser, dbPassword, dbHost, dbPort, dbName)

	log.Printf("Connecting to DB: user=%s, host=%s:%s, db=%s",
		dbUser, dbHost, dbPort, dbName)

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Fatal("DB not connect:", err)
		return nil
	}

	if err := pool.Ping(context.Background()); err != nil {
		log.Fatal("DB not responding:", err)
		return nil
	}

	log.Println("DB connected")
	return pool
}

func PostHandleSignUp(c echo.Context) error {
	var req SignUpReq

	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, Response{
			Status:  "Error",
			Message: "Incorrect format request",
		})
	}

	if req.Name == "" || req.Password == "" {
		return c.JSON(http.StatusBadRequest, Response{
			Status:  "Error",
			Message: "Username and password are required",
		})
	}

	pool := LoadDB()
	defer pool.Close()

	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, Response{
			Status:  "Error",
			Message: "Password not hashed",
		})
	}

	query := `INSERT INTO users ("Name", "Password", "public_key") VALUES ($1, $2, $3) RETURNING id`

	var userId int
	err = pool.QueryRow(
		context.Background(),
		query,
		req.Name,
		hashedPassword,
		req.Public_key,
	).Scan(&userId)

	if err != nil {
		log.Println("Error inserting user:", err)
		return c.JSON(http.StatusInternalServerError, Response{
			Status:  "Error",
			Message: "User with this name already exists or DB error",
		})
	}

	return c.JSON(http.StatusCreated, Response{
		Status:  "Success",
		Message: fmt.Sprintf("User %s created in DB with ID %d", req.Name, userId),
	})
}

func PostHandleSignIn(c echo.Context) error {
	var req SignInReq

	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, Response{
			Status:  "Error",
			Message: "Uncorect form request",
		})
	}

	if req.Name == "" || req.Password == "" {
		return c.JSON(http.StatusBadRequest, Response{
			Status:  "Error",
			Message: "Username and password are required",
		})
	}

	pool := LoadDB()
	defer pool.Close()

	query := `SELECT id, "Name", "Password" FROM users WHERE "Name" = $1`

	var userID int
	var name string
	var hashedPassword string

	errr := pool.QueryRow(
		context.Background(),
		query,
		req.Name,
	).Scan(&userID, &name, &hashedPassword)

	if errr != nil {
		log.Println("User not found:", errr)
		return c.JSON(http.StatusUnauthorized, Response{
			Status:  "Error",
			Message: "Invalid username or password",
		})
	}

	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password))
	if err != nil {
		log.Println("Password mismatch:", err)
		return c.JSON(http.StatusUnauthorized, Response{
			Status:  "Error",
			Message: "Invalid username or password",
		})
	}

	token, err := generateToken(userID, name)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, Response{
			Status:  "Error",
			Message: "Failed to generate token",
		})
	}

	return c.JSON(http.StatusOK, SignInResp{
		Status:  "Success",
		Message: "Login soccessful",
		Token:   token,
	})
}

func SendMessage(c echo.Context) error {
	authHeader := c.Request().Header.Get("Authorization")

	if authHeader == "" {
		return c.JSON(http.StatusUnauthorized, Response{
			Status:  "Error",
			Message: "Missing auth token",
		})
	}

	TokenS := authHeader[7:]

	userID, username, err := checkToken(TokenS)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, Response{
			Status:  "Error",
			Message: "Invalid token",
		})
	}

	var req SendMessageReq

	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, Response{
			Status:  "Error",
			Message: "Incorect format request",
		})
	}

	if req.Text == "" {
		return c.JSON(http.StatusBadRequest, Response{
			Status:  "Error",
			Message: "Message text is required",
		})
	}

	pool := LoadDB()
	defer pool.Close()

	var TouserId int
	var TouserName string

	query := `SELECT id, "Name" FROM "users" WHERE id = $1`

	errr := pool.QueryRow(
		context.Background(),
		query,
		req.ToUserID,
	).Scan(&TouserId, &TouserName)

	if errr != nil {
		return c.JSON(http.StatusUnauthorized, Response{
			Status:  "Error",
			Message: "Recipient not found",
		})
	}

	query1 := `INSERT INTO "messages" ("Text", "author", "id_user", "to_user_id", "to_name") VALUES ($1, $2, $3, $4, $5) RETURNING id`

	var MessageID int
	err1 := pool.QueryRow(
		context.Background(),
		query1,
		req.Text,
		username,
		userID,
		req.ToUserID,
		TouserName,
	).Scan(&MessageID)

	if err1 != nil {
		log.Println("Error saving message:", err1)
		return c.JSON(http.StatusInternalServerError, Response{
			Status:  "Error",
			Message: "Failed to save message",
		})
	}

	return c.JSON(http.StatusCreated, Response{
		Status:  "Success",
		Message: fmt.Sprintf("Message sent to %s (ID: %d)", TouserName, MessageID),
	})
}

func GetMessages(c echo.Context) error {
	authHeader := c.Request().Header.Get("Authorization")

	if authHeader == "" {
		return c.JSON(http.StatusUnauthorized, Response{
			Status:  "Error",
			Message: "Missing auth token",
		})
	}

	TokenS := authHeader[7:]

	userID, _, err := checkToken(TokenS)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, Response{
			Status:  "Error",
			Message: "Invalid token",
		})
	}

	pool := LoadDB()
	defer pool.Close()

	query := `SELECT id, "Text", author, to_name, created_at FROM messages WHERE id_user=$1 OR to_user_id=$1 ORDER BY created_at ASC`

	rows, err := pool.Query(context.Background(), query, userID)

	if err != nil {
		log.Println("Error fetching messages:", err)
		return c.JSON(http.StatusInternalServerError, Response{
			Status:  "Error",
			Message: "Failed to fetch messages",
		})
	}

	defer rows.Close()

	var messages []MessageResp
	for rows.Next() {
		var msg MessageResp
		var createdAt time.Time

		err := rows.Scan(
			&msg.ID,
			&msg.Text,
			&msg.From,
			&msg.To,
			&createdAt,
		)
		if err != nil {
			log.Println("Error scanning message:", err)
			continue
		}

		msg.Created = createdAt.Format("2006-01-02 15:04:05")
		messages = append(messages, msg)
	}

	return c.JSON(http.StatusOK, messages)
}

func GetDialog(c echo.Context) error {
	authHeader := c.Request().Header.Get("Authorization")

	if authHeader == "" {
		return c.JSON(http.StatusUnauthorized, Response{
			Status:  "Error",
			Message: "Missing auth token",
		})
	}

	TokenS := authHeader[7:]

	userID, _, err := checkToken(TokenS)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, Response{
			Status:  "Error",
			Message: "Invalid token",
		})
	}

	outherUserID, err := strconv.Atoi(c.Param("user_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, Response{
			Status:  "Error",
			Message: "Invalid user ID",
		})
	}

	pool := LoadDB()
	defer pool.Close()

	var outherName string

	err1 := pool.QueryRow(
		context.Background(),
		`SELECT "Name" FROM users WHERE id = $1`,
		outherUserID,
	).Scan(&outherName)

	if err1 != nil {
		return c.JSON(http.StatusNotFound, Response{
			Status:  "Error",
			Message: "User not found",
		})
	}

	query := `SELECT id, "Text", author, to_name, created_at FROM messages
	WHERE (id_user = $1 AND to_user_id = $2) OR (id_user = $2 AND to_user_id = $1) ORDER BY created_at ASC`

	rows, err := pool.Query(context.Background(), query, userID, outherUserID)

	if err != nil {
		log.Println("Error fetching messages:", err)
		return c.JSON(http.StatusInternalServerError, Response{
			Status:  "Error",
			Message: "Failed to fetch messages",
		})
	}

	defer rows.Close()

	var messages []MessageResp
	for rows.Next() {
		var msg MessageResp
		var createdAt time.Time

		err := rows.Scan(
			&msg.ID,
			&msg.Text,
			&msg.From,
			&msg.To,
			&createdAt,
		)
		if err != nil {
			log.Println("Error scanning message:", err)
			continue
		}

		msg.Created = createdAt.Format("2006-01-02 15:04:05")
		messages = append(messages, msg)
	}

	return c.JSON(http.StatusOK, messages)
}

func GetUsers(c echo.Context) error {
	authHeader := c.Request().Header.Get("Authorization")

	if authHeader == "" {
		return c.JSON(http.StatusUnauthorized, Response{
			Status:  "Error",
			Message: "Missing auth token",
		})
	}

	TokenS := authHeader[7:]

	userID, _, err := checkToken(TokenS)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, Response{
			Status:  "Error",
			Message: "Invalid token",
		})
	}

	pool := LoadDB()
	defer pool.Close()

	query := `SELECT id, "Name" FROM users WHERE id != $1 ORDER BY "Name" ASC`

	rows, err := pool.Query(context.Background(), query, userID)
	if err != nil {
		log.Println("Error fetching users:", err)
		return c.JSON(http.StatusInternalServerError, Response{
			Status:  "Error",
			Message: "Failed to fetch users",
		})
	}
	defer rows.Close()

	var users []map[string]interface{}
	for rows.Next() {
		var id int
		var name string
		err := rows.Scan(&id, &name)
		if err != nil {
			log.Println("Error scanning user:", err)
			continue
		}

		users = append(users, map[string]interface{}{
			"id":   id,
			"name": name,
		})
	}

	return c.JSON(http.StatusOK, users)
}

func main() {
	pool := LoadDB()
	if pool == nil {
		log.Fatal("Failed to connect to database")
	}
	defer pool.Close()

	e := echo.New()

	e.POST("/sign_up", PostHandleSignUp)
	e.POST("/sign_in", PostHandleSignIn)
	e.POST("/send_message", SendMessage)
	e.GET("/messages", GetMessages)
	e.GET("/messages/:user_id", GetDialog)
	e.GET("/users", GetUsers)

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Messenger API is running!")
	})

	log.Println("Server started on :8080")
	e.Start(":8080")
}
