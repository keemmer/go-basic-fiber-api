package main

import (
	"database/sql"
	"fmt"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	jwtware "github.com/gofiber/jwt/v2"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

const jwtSecret = "keemmer-secret-123456"

func main() {
	var err error
	db, err = sql.Open("mysql", "root:P@ssw0rd@tcp(192.168.1.8:3306)/fiber_learning")
	if err != nil {
		panic(err)
	}

	app := fiber.New()
	app.Use("hello", jwtware.New(jwtware.Config{
		SigningMethod: "HS256",
		SigningKey:    []byte(jwtSecret),
		SuccessHandler: func(c *fiber.Ctx) error {
			return c.Next()
		},
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			return fiber.ErrUnauthorized
		},
	}))

	app.Post("/signup", Signup)
	app.Post("/login", Login)
	app.Post("/hello", Hello)

	app.Listen(":8000")
}

func Signup(c *fiber.Ctx) error {
	req := SignupRequest{}
	err := c.BodyParser(&req)
	if err != nil {
		return err
	}
	if req.Username == "" || req.Password == "" {
		return fiber.ErrUnprocessableEntity
	}

	password, err := bcrypt.GenerateFromPassword([]byte(req.Password), 10)
	if err != nil {
		return fiber.NewError(fiber.StatusUnprocessableEntity, err.Error())
	}

	query := "insert  users (username, password) values (?, ?)"
	result, err := db.Exec(query, req.Username, string(password))
	if err != nil {
		return fiber.NewError(fiber.StatusUnprocessableEntity, err.Error())
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fiber.NewError(fiber.StatusUnprocessableEntity, err.Error())
	}
	user := User{
		Id:       int(id),
		Username: req.Username,
		Password: string(password),
	}

	return c.Status(fiber.StatusCreated).JSON(user)
}
func Login(c *fiber.Ctx) error {
	req := LoginRequest{}
	err := c.BodyParser(&req)

	if err != nil {
		return err
	}

	if req.Username == "" || req.Password == "" {
		return fiber.ErrUnprocessableEntity
	}

	user := User{}
	query := "select id,username,password from users where username=?"
	// rows, err := db.Query(query, req.Username)
	rows := db.QueryRow(query, req.Username)
	// if err != nil {
	// 	return fiber.NewError(fiber.StatusNotFound, err.Error())
	// }
	// for rows.Next() {
	err = rows.Scan(&user.Id, &user.Username, &user.Password)

	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}

	// }
	fmt.Println(user)
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))

	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}

	cliams := jwt.StandardClaims{
		Issuer:    strconv.Itoa(int(user.Id)),
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, cliams)
	token, err := jwtToken.SignedString([]byte(jwtSecret))
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}

	// return c.SendStatus(fiber.StatusOK)
	return c.JSON(fiber.Map{
		"accessToken": token,
	})
}

func Hello(c *fiber.Ctx) error {
	return c.SendString("Hello fiber app")
}

type User struct {
	Id       int    `db:"id" json:"id"`
	Username string `db:"username" json:"username"`
	Password string `db:"password" json:"password"`
}
type SignupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func Fiber() {
	// app := fiber.New(fiber.Config{
	// 	Prefork: true,
	// })
	app := fiber.New(fiber.Config{
		Prefork: true,
	})

	// Middleware
	// app.Use(func(c *fiber.Ctx) error {
	// 	fmt.Println("before")
	// 	err := c.Next()
	// 	fmt.Println("after")
	// 	return err
	// })
	app.Use("/hello", func(c *fiber.Ctx) error {
		c.Locals("name", "keemer")
		fmt.Println("before")
		err := c.Next()
		fmt.Println("after")
		return err
	})

	app.Use(requestid.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "*",
		AllowHeaders: "*",
	}))

	app.Use(logger.New(logger.Config{
		TimeZone: "Asia/Bangkok",
	}))

	// Get
	app.Get("/hello", func(c *fiber.Ctx) error {
		fmt.Println("run hello")
		name := c.Locals("name")
		return c.SendString(fmt.Sprintf("Get: Hello %v", name))
	})
	// Post
	app.Post("/hello", func(c *fiber.Ctx) error {
		return c.SendString("Post: Hello keemmer")
	})

	// Parameters optional
	app.Get("hello/param/:name/:surname?", func(c *fiber.Ctx) error {
		name := c.Params("name")
		surname := c.Params("surname")
		return c.SendString("name : " + name + " surname: " + surname)
	})

	// ParamsInt
	app.Get("/hello/id/:id", func(c *fiber.Ctx) error {
		id, err := c.ParamsInt("id")
		if err != nil {
			return fiber.ErrBadRequest
		}
		return c.SendString(fmt.Sprintf("ID = %v", id))
	})

	// Query returns
	app.Get("/query", func(c *fiber.Ctx) error {
		name := c.Query("name")
		surname := c.Query("surename")
		return c.SendString("name: " + name + " surname: " + surname)
	})

	// Query parser
	app.Get("/query2", func(c *fiber.Ctx) error {
		person := Person{}
		c.QueryParser(&person)
		return c.JSON(person)
	})

	// Wildcard
	app.Get("wildcards/*", func(c *fiber.Ctx) error {
		wildcard := c.Params("*")
		return c.SendString(wildcard)
	})

	// Static file
	app.Static("/", "./wwwroot", fiber.Static{
		Index:         "index.html",
		CacheDuration: time.Second * 10,
	})

	app.Get("/error", func(c *fiber.Ctx) error {
		fmt.Println("error handler")
		return fiber.NewError(fiber.StatusNotFound, "content not found")
	})

	// Group
	v1 := app.Group("/v1", func(c *fiber.Ctx) error {
		c.Set("Version", "v1")
		return c.Next()
	})
	v1.Group("/hello", func(c *fiber.Ctx) error {
		return c.SendString("hello v1")
	})

	v2 := app.Group("/v2", func(c *fiber.Ctx) error {
		c.Set("Version", "v2")
		return c.Next()
	})
	v2.Group("/hello", func(c *fiber.Ctx) error {
		return c.SendString("hello v2")
	})

	// Mount
	userApp := fiber.New()
	userApp.Get("/login", func(c *fiber.Ctx) error {
		return c.SendString("login")
	})
	app.Mount("/user", userApp)

	app.Server().MaxConnsPerIP = 1
	app.Get("/server", func(c *fiber.Ctx) error {
		time.Sleep(time.Second * 10)
		return c.SendString("server")
	})

	app.Get("/env", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"BaseURL":     c.BaseURL(),
			"Hostname":    c.Hostname(),
			"Ip":          c.IP(),
			"Ips":         c.IPs(),
			"OriginalURL": c.OriginalURL(),
			"Path":        c.Path(),
			"Protocol":    c.Protocol(),
			"Subdomain":   c.Subdomains(),
		})
	})

	// Body
	app.Get("/body", func(c *fiber.Ctx) error {
		fmt.Printf("IsJson: %v\n", c.Is("json"))
		fmt.Println(string(c.Body()))

		person := Person{}
		err := c.BodyParser(&person)
		if err != nil {
			return err
		}
		fmt.Println(person)
		return nil
	})
	app.Get("/body2", func(c *fiber.Ctx) error {
		fmt.Printf("IsJson: %v\n", c.Is("json"))
		// fmt.Println(string(c.Body()))

		data := map[string]interface{}{}
		err := c.BodyParser(&data)
		if err != nil {
			return err
		}
		fmt.Println(data)
		return nil
	})

	app.Listen(":8000")
}

type Person struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
}
