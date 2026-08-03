package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Id         int    `json:"id"`
	Name       string `json:"name"`
	Password   string `json:"password"`
	Public_key string `json:"public_key"`
}

type Message struct {
	Id      int    `json:"id"`
	Text    string `json:"text"`
	Author  string `json:"author"`
	Id_user int    `json:"id_user"`
}

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
		c.JSON(http.StatusBadRequest, Response{
			Status:  "Error",
			Message: "Uncorect form request",
		})
	}

	if req.Name == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, Response{
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
		c.JSON(http.StatusInternalServerError, Response{
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

func main() {
	pool := LoadDB()
	if pool == nil {
		log.Fatal("Failed to connect to database")
	}
	defer pool.Close()

	e := echo.New()

	e.POST("/sign_up", PostHandleSignUp)
	e.POST("/sign_in", PostHandleSignIn)

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Messenger API is running!")
	})

	log.Println("Server started on :8080")
	e.Start(":8080")
}
