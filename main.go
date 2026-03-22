package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// --- Models ---
type User struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Username     string    `gorm:"uniqueIndex" json:"username"`
	PasswordHash string    `json:"-"`    // Don't return password
	Role         string    `json:"role"` // admin, cashier
	CreatedAt    time.Time `json:"created_at"`
}

type Product struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Barcode   string    `gorm:"uniqueIndex" json:"barcode"`
	Name      string    `json:"name"`
	Price     float64   `json:"price"`
	CostPrice float64   `json:"cost_price"`
	Stock     int       `json:"stock"`
	Category  string    `json:"category"`
	Unit      string    `json:"unit"`
	Image     string    `json:"image"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Category struct {
	ID   uint   `gorm:"primaryKey" json:"id"`
	Name string `json:"name"`
}

type Unit struct {
	ID   uint   `gorm:"primaryKey" json:"id"`
	Name string `json:"name"`
}

type TransactionItem struct {
	ID            uint    `gorm:"primaryKey" json:"id"`
	TransactionID uint    `json:"transaction_id"`
	ProductID     uint    `json:"product_id"`
	ProductName   string  `json:"product_name"`
	Qty           int     `json:"qty"`
	Price         float64 `json:"price"`
	CostPrice     float64 `json:"cost_price"`
}

type Transaction struct {
	ID            uint              `gorm:"primaryKey" json:"id"`
	TotalAmount   float64           `json:"total_amount"`
	PaymentMethod string            `json:"payment_method"`
	CreatedAt     time.Time         `json:"created_at"`
	Items         []TransactionItem `json:"items" gorm:"foreignKey:TransactionID"`
}

var DB *gorm.DB
var jwtSecret = []byte("SUPER_SECRET_KEY_CHANGE_THIS") // In prod, use ENV variable

func ConnectDB() {
	dsn := "host=localhost user=postgres password=12345678 dbname=postgres port=5432 sslmode=disable TimeZone=Asia/Jakarta"
	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Println("Failed to connect to Database. Ensure Postgres is running and credentials are correct.")
		log.Println("Error:", err)
		return
	}

	log.Println("Connected to Database!")
	DB.AutoMigrate(&Product{}, &Transaction{}, &TransactionItem{}, &Category{}, &Unit{}, &User{})
}

// --- Auth Helpers ---
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Middleware to protect routes
func Protected() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
		}

		tokenString := authHeader[7:] // Remove "Bearer "
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			return c.Status(401).JSON(fiber.Map{"error": "Invalid Token"})
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if ok && token.Valid {
			c.Locals("user_id", claims["user_id"])
			c.Locals("role", claims["role"])
		}

		return c.Next()
	}
}

func initAdmin() {
	var count int64
	DB.Model(&User{}).Count(&count)
	if count == 0 {
		hash, _ := HashPassword("admin123")
		user := User{Username: "admin", PasswordHash: hash, Role: "admin"}
		DB.Create(&user)
		log.Println("--- ADMIN ACCOUNT CREATED ---")
		log.Println("Username: admin")
		log.Println("Password: admin123")
		log.Println("-----------------------------")
	}
}

func main() {
	ConnectDB()
	initAdmin() // Ensure admin exists

	// Ensure uploads directory exists
	if _, err := os.Stat("./uploads"); os.IsNotExist(err) {
		os.Mkdir("./uploads", 0755)
	}

	app := fiber.New()
	app.Use(cors.New())
	app.Static("/uploads", "./uploads")

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Kasir Backend is Running & Connected to DB!")
	})

	// --- AUTH ENDPOINTS ---

	app.Post("/api/login", func(c *fiber.Ctx) error {
		type LoginRequest struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		var req LoginRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid Request"})
		}

		var user User
		if err := DB.Where("username = ?", req.Username).First(&user).Error; err != nil {
			return c.Status(401).JSON(fiber.Map{"error": "User not found"})
		}

		if !CheckPasswordHash(req.Password, user.PasswordHash) {
			return c.Status(401).JSON(fiber.Map{"error": "Incorrect Password"})
		}

		// Generate JWT
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user_id": user.ID,
			"role":    user.Role,
			"exp":     time.Now().Add(time.Hour * 24).Unix(), // 24 hours
		})

		t, err := token.SignedString(jwtSecret)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Could not login"})
		}

		return c.JSON(fiber.Map{"token": t, "user": user})
	})

	// Init Admin User
	app.Post("/api/seed-admin", func(c *fiber.Ctx) error {
		var count int64
		DB.Model(&User{}).Count(&count)
		if count > 0 {
			return c.Status(400).JSON(fiber.Map{"message": "Admin already exists"})
		}

		hash, _ := HashPassword("admin123")
		user := User{Username: "admin", PasswordHash: hash, Role: "admin"}
		DB.Create(&user)
		return c.JSON(fiber.Map{"message": "Admin created (admin / admin123)"})
	})

	// --- USER MANAGEMENT (ADMIN ONLY) ---

	app.Get("/api/users", Protected(), func(c *fiber.Ctx) error {
		if c.Locals("role") != "admin" {
			return c.Status(403).JSON(fiber.Map{"error": "Admin required"})
		}
		var users []User
		DB.Order("id asc").Find(&users)
		return c.JSON(users)
	})

	app.Post("/api/users", Protected(), func(c *fiber.Ctx) error {
		if c.Locals("role") != "admin" {
			return c.Status(403).JSON(fiber.Map{"error": "Admin required"})
		}

		type CreateUserRequest struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		req := new(CreateUserRequest)
		if err := c.BodyParser(req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
		}

		hash, _ := HashPassword(req.Password)
		user := User{Username: req.Username, PasswordHash: hash, Role: req.Role}

		if err := DB.Create(&user).Error; err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Could not create user. Username might be taken."})
		}
		return c.JSON(user)
	})

	app.Put("/api/users/:id", Protected(), func(c *fiber.Ctx) error {
		if c.Locals("role") != "admin" {
			return c.Status(403).JSON(fiber.Map{"error": "Admin required"})
		}
		id := c.Params("id")
		var user User
		if err := DB.First(&user, id).Error; err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "User not found"})
		}

		type UpdateUserRequest struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		req := new(UpdateUserRequest)
		if err := c.BodyParser(req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
		}

		user.Username = req.Username
		user.Role = req.Role
		if req.Password != "" {
			user.PasswordHash, _ = HashPassword(req.Password)
		}

		DB.Save(&user)
		return c.JSON(user)
	})

	app.Delete("/api/users/:id", Protected(), func(c *fiber.Ctx) error {
		if c.Locals("role") != "admin" {
			return c.Status(403).JSON(fiber.Map{"error": "Admin required"})
		}
		id := c.Params("id")

		// Prevent deleting self (optional, but good practice)
		// if fmt.Sprintf("%v", c.Locals("user_id")) == id { return error }

		DB.Delete(&User{}, id)
		return c.JSON(fiber.Map{"message": "User deleted"})
	})

	// --- PROFILE UPDATE (SELF) ---
	app.Put("/api/profile", Protected(), func(c *fiber.Ctx) error {
		userId := c.Locals("user_id")
		var user User
		if err := DB.First(&user, userId).Error; err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "User not found"})
		}

		type ProfileRequest struct {
			Password string `json:"password"`
		}
		req := new(ProfileRequest)
		if err := c.BodyParser(req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
		}

		if req.Password != "" {
			user.PasswordHash, _ = HashPassword(req.Password)
			DB.Save(&user)
			return c.JSON(fiber.Map{"message": "Password updated"})
		}
		return c.Status(400).JSON(fiber.Map{"error": "No changes made"})
	})

	// Seed Data Endpoint
	app.Post("/api/seed", func(c *fiber.Ctx) error {
		// Seed Categories
		categories := []Category{
			{Name: "Makanan"},
			{Name: "Minuman"},
			{Name: "Snack"},
			{Name: "Rokok"},
			{Name: "Sabun"},
			{Name: "Lainnya"},
		}

		units := []Unit{
			{Name: "Pcs"},
			{Name: "Pack"},
			{Name: "Box"},
			{Name: "Kg"},
			{Name: "Liter"},
			{Name: "Dus"},
		}

		products := []Product{
			{Barcode: "8998866200578", Name: "Indomie Goreng Rendang", Price: 3500, CostPrice: 2800, Stock: 50, Category: "Makanan", Unit: "Pcs"},
			{Barcode: "8991002101104", Name: "Kopi Kapal Api Mix 25g", Price: 1500, CostPrice: 1100, Stock: 100, Category: "Minuman", Unit: "Pcs"},
			{Barcode: "8996001600399", Name: "Le Mineral 1,5 L", Price: 7000, CostPrice: 5500, Stock: 6, Category: "Minuman", Unit: "Pcs"},
			{Barcode: "ROTI001", Name: "Roti O Original", Price: 12000, CostPrice: 8000, Stock: 10, Category: "Makanan", Unit: "Pcs"},
			{Barcode: "8999909096004", Name: "Sampoerna Mild 16", Price: 32000, CostPrice: 29500, Stock: 50, Category: "Rokok", Unit: "Pack"},
			{Barcode: "8996001600269", Name: "Teh Pucuk Harum 350ml", Price: 4000, CostPrice: 2800, Stock: 40, Category: "Minuman", Unit: "Pcs"},
			{Barcode: "8993175538023", Name: "Chitato Sapi Panggang", Price: 11500, CostPrice: 9500, Stock: 15, Category: "Snack", Unit: "Pcs"},
			{Barcode: "8992103451115", Name: "Sabun Lifebuoy Cair", Price: 25000, CostPrice: 19000, Stock: 12, Category: "Sabun", Unit: "Pcs"},
		}
		if DB != nil {
			// Clean Start: Clear tables
			DB.Exec("TRUNCATE TABLE products RESTART IDENTITY CASCADE")
			DB.Exec("TRUNCATE TABLE categories RESTART IDENTITY CASCADE")
			DB.Exec("TRUNCATE TABLE units RESTART IDENTITY CASCADE")
			DB.Exec("TRUNCATE TABLE users RESTART IDENTITY CASCADE") // Reset Users too only on full seed

			DB.Create(&categories)
			DB.Create(&units)
			DB.Create(&products)

			// Seed Admin
			hash, _ := HashPassword("admin123")
			admin := User{Username: "admin", PasswordHash: hash, Role: "admin"}
			DB.Create(&admin)

			return c.JSON(fiber.Map{"message": "Database Reset & Seeded!", "products": len(products), "categories": len(categories), "units": len(units)})
		}
		return c.Status(500).JSON(fiber.Map{"error": "Database not connected"})
	})

	// GET Products
	app.Get("/api/products", func(c *fiber.Ctx) error {
		products := []Product{}
		if DB != nil {
			DB.Find(&products)
		} else {
			return c.JSON([]fiber.Map{})
		}
		return c.JSON(products)
	})

	// UPDATE Product (PUT) - PROTECTED
	app.Put("/api/products/:id", Protected(), func(c *fiber.Ctx) error {
		// Check Role? (Optional: if c.Locals("role") == "admin")
		id := c.Params("id")
		var product Product
		if err := DB.First(&product, id).Error; err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "Product not found"})
		}

		// Update fields
		if v := c.FormValue("barcode"); v != "" {
			product.Barcode = v
		}
		if v := c.FormValue("name"); v != "" {
			product.Name = v
		}
		if v := c.FormValue("category"); v != "" {
			product.Category = v
		}
		if v := c.FormValue("unit"); v != "" {
			product.Unit = v
		}
		if v := c.FormValue("price"); v != "" {
			if p, err := strconv.ParseFloat(v, 64); err == nil {
				product.Price = p
			}
		}
		if v := c.FormValue("cost_price"); v != "" {
			if p, err := strconv.ParseFloat(v, 64); err == nil {
				product.CostPrice = p
			}
		}
		if v := c.FormValue("stock"); v != "" {
			if s, err := strconv.Atoi(v); err == nil {
				product.Stock = s
			}
		}

		// Handle Image Upload
		if file, err := c.FormFile("image"); err == nil {
			filename := fmt.Sprintf("%d_%s", time.Now().Unix(), file.Filename)
			c.SaveFile(file, fmt.Sprintf("./uploads/%s", filename))
			product.Image = "/uploads/" + filename
		}

		DB.Save(&product)
		return c.JSON(product)
	})

	// DELETE Product - PROTECTED
	app.Delete("/api/products/:id", Protected(), func(c *fiber.Ctx) error {
		if c.Locals("role") != "admin" {
			return c.Status(403).JSON(fiber.Map{"error": "Admin required"})
		}
		id := c.Params("id")
		DB.Delete(&Product{}, id)
		return c.JSON(fiber.Map{"message": "Product deleted"})
	})

	// CREATE Product (POST) - PROTECTED
	app.Post("/api/products", Protected(), func(c *fiber.Ctx) error {
		product := new(Product)
		product.Barcode = c.FormValue("barcode")
		product.Name = c.FormValue("name")
		product.Category = c.FormValue("category")
		product.Unit = c.FormValue("unit")

		if p, err := strconv.ParseFloat(c.FormValue("price"), 64); err == nil {
			product.Price = p
		}
		if cp, err := strconv.ParseFloat(c.FormValue("cost_price"), 64); err == nil {
			product.CostPrice = cp
		}
		if s, err := strconv.Atoi(c.FormValue("stock")); err == nil {
			product.Stock = s
		}

		if file, err := c.FormFile("image"); err == nil {
			filename := fmt.Sprintf("%d_%s", time.Now().Unix(), file.Filename)
			c.SaveFile(file, fmt.Sprintf("./uploads/%s", filename))
			product.Image = "/uploads/" + filename
		}

		if DB != nil {
			if err := DB.Create(product).Error; err != nil {
				return c.Status(500).JSON(fiber.Map{"error": err.Error()})
			}
		}
		return c.JSON(product)
	})

	// CHECKOUT - Allow Public (or protect if you want only cashier to sell)
	app.Post("/api/checkout", Protected(), func(c *fiber.Ctx) error {
		type CheckoutRequest struct {
			Total         float64           `json:"total"`
			PaymentMethod string            `json:"paymentMethod"`
			Items         []TransactionItem `json:"items"`
		}

		req := new(CheckoutRequest)
		if err := c.BodyParser(req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
		}

		tx := DB.Begin()

		transaction := Transaction{
			TotalAmount:   req.Total,
			PaymentMethod: req.PaymentMethod,
			CreatedAt:     time.Now(),
		}
		if err := tx.Create(&transaction).Error; err != nil {
			tx.Rollback()
			return c.Status(500).JSON(fiber.Map{"error": "Failed to create transaction"})
		}

		// Create Items & Deduct Stock
		for i := range req.Items {
			item := &req.Items[i]
			item.TransactionID = transaction.ID
			if err := tx.Create(item).Error; err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{"error": "Failed to save item"})
			}

			// Deduct Stock
			if err := tx.Model(&Product{}).Where("id = ?", item.ProductID).Update("stock", gorm.Expr("stock - ?", item.Qty)).Error; err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{"error": "Failed to update stock"})
			}
		}

		tx.Commit()
		return c.JSON(fiber.Map{"message": "Transaction success", "id": transaction.ID})
	})

	// GET Transactions History - Protected
	app.Get("/api/transactions", Protected(), func(c *fiber.Ctx) error {
		var transactions []Transaction
		if err := DB.Preload("Items").Order("created_at desc").Limit(50).Find(&transactions).Error; err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch transactions"})
		}
		return c.JSON(transactions)
	})

	// --- CATEGORY MANAGEMENT ---
	app.Get("/api/categories", func(c *fiber.Ctx) error { // Public Read
		var categories []Category
		DB.Order("name asc").Find(&categories)
		return c.JSON(categories)
	})

	app.Post("/api/categories", Protected(), func(c *fiber.Ctx) error {
		category := new(Category)
		if err := c.BodyParser(category); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
		}
		if DB.Create(category).Error != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to create"})
		}
		return c.JSON(category)
	})

	app.Put("/api/categories/:id", Protected(), func(c *fiber.Ctx) error {
		id := c.Params("id")
		var category Category
		if DB.First(&category, id).Error != nil {
			return c.Status(404).JSON(fiber.Map{"error": "Category not found"})
		}
		if err := c.BodyParser(&category); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
		}
		DB.Save(&category)
		return c.JSON(category)
	})

	app.Delete("/api/categories/:id", Protected(), func(c *fiber.Ctx) error {
		id := c.Params("id")
		DB.Delete(&Category{}, id)
		return c.JSON(fiber.Map{"message": "Category deleted"})
	})

	// --- UNIT MANAGEMENT ---
	app.Get("/api/units", func(c *fiber.Ctx) error {
		var units []Unit
		DB.Order("name asc").Find(&units)
		return c.JSON(units)
	})

	app.Post("/api/units", Protected(), func(c *fiber.Ctx) error {
		unit := new(Unit)
		if err := c.BodyParser(unit); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
		}
		if DB.Create(unit).Error != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to create"})
		}
		return c.JSON(unit)
	})

	app.Put("/api/units/:id", Protected(), func(c *fiber.Ctx) error {
		id := c.Params("id")
		var unit Unit
		if DB.First(&unit, id).Error != nil {
			return c.Status(404).JSON(fiber.Map{"error": "Unit not found"})
		}
		if err := c.BodyParser(&unit); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
		}
		DB.Save(&unit)
		return c.JSON(unit)
	})

	app.Delete("/api/units/:id", Protected(), func(c *fiber.Ctx) error {
		id := c.Params("id")
		DB.Delete(&Unit{}, id)
		return c.JSON(fiber.Map{"message": "Unit deleted"})
	})

	// --- REPORTS ---
	app.Get("/api/reports/chart", Protected(), func(c *fiber.Ctx) error {
		period := c.Query("period", "daily")
		var results []struct {
			Date  string  `json:"date"`
			Total float64 `json:"total"`
		}

		// PostgreSQL Date Format Syntax
		dateFormat := "YYYY-MM-DD" // Daily
		if period == "monthly" {
			dateFormat = "YYYY-MM"
		} else if period == "yearly" {
			dateFormat = "YYYY"
		}

		// Raw SQL for aggregation (Compatible with PostgreSQL)
		err := DB.Model(&Transaction{}).
			Select("TO_CHAR(created_at, '" + dateFormat + "') as date, SUM(total_amount) as total").
			Group("TO_CHAR(created_at, '" + dateFormat + "')").
			Order("date asc").
			Scan(&results).Error

		if err != nil {
			log.Println("Report Error:", err)
			return c.Status(500).JSON(fiber.Map{"error": "Failed to generate report"})
		}
		return c.JSON(results)
	})

	log.Fatal(app.Listen(":3000"))
}
