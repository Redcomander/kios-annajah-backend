package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
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
	ID             uint       `gorm:"primaryKey" json:"id"`
	Barcode        string     `gorm:"uniqueIndex" json:"barcode"`
	Name           string     `json:"name"`
	Price          float64    `json:"price"`
	CostPrice      float64    `json:"cost_price"`
	Stock          int        `json:"stock"`
	Category       string     `json:"category"`
	Unit           string     `json:"unit"`
	Image          string     `json:"image"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	NearestExpired *time.Time `gorm:"-" json:"nearest_expired_at,omitempty"`
	NearExpiry     bool       `gorm:"-" json:"near_expiry"`
	LowStock       bool       `gorm:"-" json:"low_stock"`
}

type ProductBatch struct {
	ID           uint       `gorm:"primaryKey" json:"id"`
	ProductID    uint       `gorm:"index" json:"product_id"`
	Qty          int        `json:"qty"`
	RemainingQty int        `json:"remaining_qty"`
	ExpiredAt    *time.Time `json:"expired_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type Category struct {
	ID   uint   `gorm:"primaryKey" json:"id"`
	Name string `gorm:"uniqueIndex" json:"name"`
}

type Unit struct {
	ID   uint   `gorm:"primaryKey" json:"id"`
	Name string `gorm:"uniqueIndex" json:"name"`
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
	IsVoided      bool              `gorm:"default:false" json:"is_voided"`
	VoidedAt      *time.Time        `json:"voided_at,omitempty"`
	VoidReason    string            `json:"void_reason,omitempty"`
	Items         []TransactionItem `json:"items" gorm:"foreignKey:TransactionID"`
}

type ActivityLog struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    uint      `json:"user_id"`
	Username  string    `json:"username"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Details   string    `json:"details"`
	CreatedAt time.Time `json:"created_at"`
}

var DB *gorm.DB
var jwtSecret []byte
var uploadsDir string

const lowStockThreshold = 10
const nearExpiryDays = 14

func getEnv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	return value
}

func ensureDir(dirPath string) error {
	if dirPath == "" {
		return nil
	}

	return os.MkdirAll(dirPath, 0755)
}

func resolveDatabasePath() string {
	return getEnv("DATABASE_PATH", filepath.Join(".", "data", "kios-annajah.db"))
}

func resolveDatabaseDriver() string {
	return strings.ToLower(getEnv("DATABASE_DRIVER", "sqlite"))
}

func resolveDatabaseURL() string {
	return getEnv("DATABASE_URL", "")
}

func resolveUploadsDir() string {
	return getEnv("UPLOADS_DIR", filepath.Join(".", "uploads"))
}

func ConnectDB() error {
	dbDriver := resolveDatabaseDriver()

	var err error
	switch dbDriver {
	case "sqlite":
		databasePath := resolveDatabasePath()
		if err := ensureDir(filepath.Dir(databasePath)); err != nil {
			return fmt.Errorf("create database directory: %w", err)
		}
		DB, err = gorm.Open(sqlite.Open(databasePath), &gorm.Config{})
		if err != nil {
			return fmt.Errorf("connect sqlite database: %w", err)
		}
	case "postgres", "postgresql":
		databaseURL := resolveDatabaseURL()
		if databaseURL == "" {
			return fmt.Errorf("DATABASE_URL is required when DATABASE_DRIVER=postgres")
		}
		DB, err = gorm.Open(postgres.Open(databaseURL), &gorm.Config{})
		if err != nil {
			return fmt.Errorf("connect postgres database: %w", err)
		}
	default:
		return fmt.Errorf("unsupported DATABASE_DRIVER: %s", dbDriver)
	}

	sqlDB, err := DB.DB()
	if err != nil {
		return fmt.Errorf("open database handle: %w", err)
	}

	if err := sqlDB.Ping(); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}

	log.Println("Connected to Database!")

	if err := DB.AutoMigrate(&Product{}, &ProductBatch{}, &Transaction{}, &TransactionItem{}, &Category{}, &Unit{}, &User{}, &ActivityLog{}); err != nil {
		return fmt.Errorf("auto migrate schema: %w", err)
	}

	return nil
}

func parseOptionalDate(value string) (*time.Time, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, nil
	}

	t, err := time.Parse("2006-01-02", trimmed)
	if err != nil {
		return nil, err
	}

	return &t, nil
}

func enrichProductsWithAlerts(products []Product) []Product {
	now := time.Now()
	nearExpiryCutoff := now.AddDate(0, 0, nearExpiryDays)

	for i := range products {
		products[i].LowStock = products[i].Stock <= lowStockThreshold

		var batch ProductBatch
		err := DB.Where("product_id = ? AND remaining_qty > 0 AND expired_at IS NOT NULL", products[i].ID).
			Order("expired_at asc").
			First(&batch).Error
		if err == nil && batch.ExpiredAt != nil {
			products[i].NearestExpired = batch.ExpiredAt
			products[i].NearExpiry = batch.ExpiredAt.Before(nearExpiryCutoff) || batch.ExpiredAt.Equal(nearExpiryCutoff)
		}
	}

	return products
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

func logActivity(c *fiber.Ctx, action, target, details string) {
	userIDFloat, _ := c.Locals("user_id").(float64)
	username, _ := c.Locals("username").(string)
	entry := ActivityLog{
		UserID:   uint(userIDFloat),
		Username: username,
		Action:   action,
		Target:   target,
		Details:  details,
	}
	DB.Create(&entry)
}

// Middleware to protect routes
func Protected() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(401).JSON(fiber.Map{"error": "Unauthorized"})
		}

		if !strings.HasPrefix(authHeader, "Bearer ") || len(authHeader) <= len("Bearer ") {
			return c.Status(401).JSON(fiber.Map{"error": "Invalid Token"})
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
			c.Locals("username", claims["username"])
		}

		return c.Next()
	}
}

func initAdmin() error {
	var count int64
	if err := DB.Model(&User{}).Count(&count).Error; err != nil {
		return fmt.Errorf("count users: %w", err)
	}

	if count == 0 {
		initialPassword := getEnv("ADMIN_INITIAL_PASSWORD", "admin123")
		hash, err := HashPassword(initialPassword)
		if err != nil {
			return fmt.Errorf("hash initial admin password: %w", err)
		}

		user := User{Username: "admin", PasswordHash: hash, Role: "admin"}
		if err := DB.Create(&user).Error; err != nil {
			return fmt.Errorf("create admin user: %w", err)
		}

		log.Println("Initial admin user created.")
	}

	return nil
}

func ensureDefaultMasterData() error {
	defaultCategories := []string{"Makanan", "Minuman", "Snack", "Rokok", "Sabun", "Bumbu", "Beras", "ATK", "Lainnya"}
	defaultUnits := []string{"Pcs", "Pack", "Box", "Kg", "Gram", "Liter", "Ml", "Dus", "Botol", "Sachet"}

	for _, name := range defaultCategories {
		category := Category{Name: name}
		if err := DB.Where("name = ?", name).FirstOrCreate(&category).Error; err != nil {
			return fmt.Errorf("ensure default category %s: %w", name, err)
		}
	}

	for _, name := range defaultUnits {
		unit := Unit{Name: name}
		if err := DB.Where("name = ?", name).FirstOrCreate(&unit).Error; err != nil {
			return fmt.Errorf("ensure default unit %s: %w", name, err)
		}
	}

	return nil
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found. Falling back to OS environment variables.")
	}

	jwtSecret = []byte(getEnv("JWT_SECRET", "SUPER_SECRET_KEY_CHANGE_THIS"))
	uploadsDir = resolveUploadsDir()

	if err := ConnectDB(); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	if err := initAdmin(); err != nil {
		log.Fatalf("Failed to initialize admin user: %v", err)
	}

	if err := ensureDefaultMasterData(); err != nil {
		log.Fatalf("Failed to initialize default categories and units: %v", err)
	}

	if err := ensureDir(uploadsDir); err != nil {
		log.Fatalf("Failed to create uploads directory: %v", err)
	}

	app := fiber.New()
	app.Use(cors.New(cors.Config{
		AllowOrigins: getEnv("CORS_ALLOW_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"),
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
	}))
	app.Static("/uploads", uploadsDir)

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
			"user_id":  user.ID,
			"username": user.Username,
			"role":     user.Role,
			"exp":      time.Now().Add(time.Hour * 24).Unix(), // 24 hours
		})

		t, err := token.SignedString(jwtSecret)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Could not login"})
		}

		return c.JSON(fiber.Map{"token": t, "user": user})
	})

	if getEnv("ENABLE_DEV_SEED_ROUTES", "false") == "true" {
		app.Post("/api/seed-admin", func(c *fiber.Ctx) error {
			var count int64
			DB.Model(&User{}).Count(&count)
			if count > 0 {
				return c.Status(400).JSON(fiber.Map{"message": "Admin already exists"})
			}

			hash, err := HashPassword(getEnv("ADMIN_INITIAL_PASSWORD", "admin123"))
			if err != nil {
				return c.Status(500).JSON(fiber.Map{"error": "Failed to create admin"})
			}

			user := User{Username: "admin", PasswordHash: hash, Role: "admin"}
			DB.Create(&user)
			return c.JSON(fiber.Map{"message": "Admin created"})
		})
	}

	// --- USER MANAGEMENT (ADMIN ONLY) ---

	app.Get("/api/users", Protected(), func(c *fiber.Ctx) error {
		if c.Locals("role") != "admin" {
			return c.Status(403).JSON(fiber.Map{"error": "Admin required"})
		}
		var users []User
		if err := DB.Order("id asc").Find(&users).Error; err != nil {
			log.Println("Failed to fetch users:", err)
			return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch users"})
		}
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

		hash, err := HashPassword(req.Password)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Could not hash password"})
		}

		var existingUser User
		if err := DB.Where("username = ?", req.Username).First(&existingUser).Error; err == nil {
			return c.Status(409).JSON(fiber.Map{"error": "Username already exists"})
		}

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
			hash, err := HashPassword(req.Password)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{"error": "Could not hash password"})
			}
			user.PasswordHash = hash
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
			hash, err := HashPassword(req.Password)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{"error": "Could not hash password"})
			}
			user.PasswordHash = hash
			DB.Save(&user)
			return c.JSON(fiber.Map{"message": "Password updated"})
		}
		return c.Status(400).JSON(fiber.Map{"error": "No changes made"})
	})

	if getEnv("ENABLE_DEV_SEED_ROUTES", "false") == "true" {
		app.Post("/api/seed", func(c *fiber.Ctx) error {
			categories := []Category{{Name: "Makanan"}, {Name: "Minuman"}, {Name: "Snack"}, {Name: "Rokok"}, {Name: "Sabun"}, {Name: "Lainnya"}}
			units := []Unit{{Name: "Pcs"}, {Name: "Pack"}, {Name: "Box"}, {Name: "Kg"}, {Name: "Liter"}, {Name: "Dus"}}
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

			if DB == nil {
				return c.Status(500).JSON(fiber.Map{"error": "Database not connected"})
			}

			tx := DB.Begin()
			if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&TransactionItem{}).Error; err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{"error": "Failed to clear transaction items"})
			}
			if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&Transaction{}).Error; err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{"error": "Failed to clear transactions"})
			}
			if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&Product{}).Error; err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{"error": "Failed to clear products"})
			}
			if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&Category{}).Error; err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{"error": "Failed to clear categories"})
			}
			if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&Unit{}).Error; err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{"error": "Failed to clear units"})
			}
			if err := tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&User{}).Error; err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{"error": "Failed to clear users"})
			}

			if err := tx.Create(&categories).Error; err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{"error": "Failed to seed categories"})
			}
			if err := tx.Create(&units).Error; err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{"error": "Failed to seed units"})
			}
			if err := tx.Create(&products).Error; err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{"error": "Failed to seed products"})
			}

			hash, err := HashPassword(getEnv("ADMIN_INITIAL_PASSWORD", "admin123"))
			if err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{"error": "Failed to seed admin"})
			}
			admin := User{Username: "admin", PasswordHash: hash, Role: "admin"}
			if err := tx.Create(&admin).Error; err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{"error": "Failed to seed admin"})
			}

			tx.Commit()
			return c.JSON(fiber.Map{"message": "Database reset and seeded", "products": len(products), "categories": len(categories), "units": len(units)})
		})
	}

	// GET Products
	app.Get("/api/products", func(c *fiber.Ctx) error {
		products := []Product{}
		if DB != nil {
			DB.Find(&products)
		} else {
			return c.JSON([]fiber.Map{})
		}
		return c.JSON(enrichProductsWithAlerts(products))
	})

	// UPDATE Product (PUT) - PROTECTED (admin + cashier)
	app.Put("/api/products/:id", Protected(), func(c *fiber.Ctx) error {

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
			if err := c.SaveFile(file, filepath.Join(uploadsDir, filename)); err != nil {
				return c.Status(500).JSON(fiber.Map{"error": "Failed to save image"})
			}
			product.Image = "/uploads/" + filename
		}

		DB.Save(&product)
		logActivity(c, "edit_produk", product.Name, fmt.Sprintf("harga: %.0f, stok: %d", product.Price, product.Stock))
		return c.JSON(product)
	})

	// DELETE Product - PROTECTED (admin + cashier)
	app.Delete("/api/products/:id", Protected(), func(c *fiber.Ctx) error {
		id := c.Params("id")
		var delProduct Product
		if err := DB.First(&delProduct, id).Error; err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "Product not found"})
		}
		DB.Delete(&Product{}, id)
		logActivity(c, "hapus_produk", delProduct.Name, fmt.Sprintf("id: %d", delProduct.ID))
		return c.JSON(fiber.Map{"message": "Product deleted"})
	})

	// CREATE Product (POST) - PROTECTED (admin + cashier)
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
			if err := c.SaveFile(file, filepath.Join(uploadsDir, filename)); err != nil {
				return c.Status(500).JSON(fiber.Map{"error": "Failed to save image"})
			}
			product.Image = "/uploads/" + filename
		}

		expiredAt, err := parseOptionalDate(c.FormValue("expired_at"))
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid expired date format. Use YYYY-MM-DD"})
		}

		if DB != nil {
			if err := DB.Create(product).Error; err != nil {
				return c.Status(500).JSON(fiber.Map{"error": err.Error()})
			}

			if product.Stock > 0 {
				batch := ProductBatch{
					ProductID:    product.ID,
					Qty:          product.Stock,
					RemainingQty: product.Stock,
					ExpiredAt:    expiredAt,
				}
				if err := DB.Create(&batch).Error; err != nil {
					return c.Status(500).JSON(fiber.Map{"error": "Product created but failed to save stock batch"})
				}
			}
		}
		logActivity(c, "tambah_produk", product.Name, fmt.Sprintf("harga: %.0f, stok: %d", product.Price, product.Stock))
		return c.JSON(product)
	})

	app.Post("/api/products/:id/restock", Protected(), func(c *fiber.Ctx) error {

		type RestockRequest struct {
			Qty       int    `json:"qty"`
			ExpiredAt string `json:"expired_at"`
		}

		id := c.Params("id")
		var req RestockRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid input"})
		}

		if req.Qty <= 0 {
			return c.Status(400).JSON(fiber.Map{"error": "Qty must be greater than 0"})
		}

		expiredAt, err := parseOptionalDate(req.ExpiredAt)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid expired date format. Use YYYY-MM-DD"})
		}

		var product Product
		if err := DB.First(&product, id).Error; err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "Product not found"})
		}

		tx := DB.Begin()
		if err := tx.Model(&Product{}).Where("id = ?", product.ID).Update("stock", gorm.Expr("stock + ?", req.Qty)).Error; err != nil {
			tx.Rollback()
			return c.Status(500).JSON(fiber.Map{"error": "Failed to update stock"})
		}

		batch := ProductBatch{
			ProductID:    product.ID,
			Qty:          req.Qty,
			RemainingQty: req.Qty,
			ExpiredAt:    expiredAt,
		}
		if err := tx.Create(&batch).Error; err != nil {
			tx.Rollback()
			return c.Status(500).JSON(fiber.Map{"error": "Failed to save stock batch"})
		}

		tx.Commit()
		logActivity(c, "tambah_stok", product.Name, fmt.Sprintf("+%d unit", req.Qty))
		return c.JSON(fiber.Map{"message": "Stock updated", "batch": batch})
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
			if item.Qty <= 0 {
				tx.Rollback()
				return c.Status(400).JSON(fiber.Map{"error": "Invalid item quantity"})
			}

			var product Product
			if err := tx.First(&product, item.ProductID).Error; err != nil {
				tx.Rollback()
				return c.Status(400).JSON(fiber.Map{"error": "Product not found"})
			}

			if product.Stock < item.Qty {
				tx.Rollback()
				return c.Status(400).JSON(fiber.Map{"error": fmt.Sprintf("Insufficient stock for %s", product.Name)})
			}

			item.ProductName = product.Name
			item.Price = product.Price
			item.CostPrice = product.CostPrice
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

			remainingToDeduct := item.Qty
			var batches []ProductBatch
			if err := tx.Where("product_id = ? AND remaining_qty > 0", item.ProductID).
				Order("CASE WHEN expired_at IS NULL THEN 1 ELSE 0 END, expired_at asc, id asc").
				Find(&batches).Error; err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{"error": "Failed to update stock batch"})
			}

			for _, batch := range batches {
				if remainingToDeduct <= 0 {
					break
				}

				consume := batch.RemainingQty
				if consume > remainingToDeduct {
					consume = remainingToDeduct
				}

				if consume > 0 {
					if err := tx.Model(&ProductBatch{}).Where("id = ?", batch.ID).Update("remaining_qty", gorm.Expr("remaining_qty - ?", consume)).Error; err != nil {
						tx.Rollback()
						return c.Status(500).JSON(fiber.Map{"error": "Failed to consume stock batch"})
					}
					remainingToDeduct -= consume
				}
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

	app.Delete("/api/transactions/:id", Protected(), func(c *fiber.Ctx) error {
		if c.Locals("role") != "admin" {
			return c.Status(403).JSON(fiber.Map{"error": "Admin required"})
		}

		id := c.Params("id")

		var transaction Transaction
		if err := DB.Preload("Items").First(&transaction, id).Error; err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "Transaction not found"})
		}

		if transaction.IsVoided {
			return c.Status(400).JSON(fiber.Map{"error": "Transaction already voided"})
		}

		type voidRequest struct {
			Reason string `json:"reason"`
		}
		var req voidRequest
		_ = c.BodyParser(&req)

		tx := DB.Begin()

		for _, item := range transaction.Items {
			if err := tx.Model(&Product{}).Where("id = ?", item.ProductID).Update("stock", gorm.Expr("stock + ?", item.Qty)).Error; err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{"error": "Failed to restore stock"})
			}

			reversalBatch := ProductBatch{
				ProductID:    item.ProductID,
				Qty:          item.Qty,
				RemainingQty: item.Qty,
			}
			if err := tx.Create(&reversalBatch).Error; err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{"error": "Failed to restore stock batch"})
			}
		}

		voidedAt := time.Now()
		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			reason = "Void/refund by admin"
		}

		if err := tx.Model(&Transaction{}).Where("id = ?", transaction.ID).Updates(map[string]interface{}{
			"is_voided":   true,
			"voided_at":   voidedAt,
			"void_reason": reason,
		}).Error; err != nil {
			tx.Rollback()
			return c.Status(500).JSON(fiber.Map{"error": "Failed to mark transaction as voided"})
		}

		tx.Commit()
		return c.JSON(fiber.Map{"message": "Transaction voided and stock restored"})
	})

	app.Post("/api/transactions/:id/refund", Protected(), func(c *fiber.Ctx) error {
		if c.Locals("role") != "admin" {
			return c.Status(403).JSON(fiber.Map{"error": "Admin required"})
		}

		id := c.Params("id")

		var transaction Transaction
		if err := DB.Preload("Items").First(&transaction, id).Error; err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "Transaction not found"})
		}

		if transaction.IsVoided {
			return c.Status(400).JSON(fiber.Map{"error": "Transaction already voided"})
		}

		type voidRequest struct {
			Reason string `json:"reason"`
		}
		var req voidRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
		}

		tx := DB.Begin()

		for _, item := range transaction.Items {
			if err := tx.Model(&Product{}).Where("id = ?", item.ProductID).Update("stock", gorm.Expr("stock + ?", item.Qty)).Error; err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{"error": "Failed to restore stock"})
			}

			reversalBatch := ProductBatch{
				ProductID:    item.ProductID,
				Qty:          item.Qty,
				RemainingQty: item.Qty,
			}
			if err := tx.Create(&reversalBatch).Error; err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{"error": "Failed to restore stock batch"})
			}
		}

		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			reason = "Refund by admin"
		}
		voidedAt := time.Now()

		if err := tx.Model(&Transaction{}).Where("id = ?", transaction.ID).Updates(map[string]interface{}{
			"is_voided":   true,
			"voided_at":   voidedAt,
			"void_reason": reason,
		}).Error; err != nil {
			tx.Rollback()
			return c.Status(500).JSON(fiber.Map{"error": "Failed to mark transaction as refunded"})
		}

		tx.Commit()
		return c.JSON(fiber.Map{"message": "Transaction refunded and stock restored"})
	})

	// --- CATEGORY MANAGEMENT ---
	app.Get("/api/categories", func(c *fiber.Ctx) error { // Public Read
		var categories []Category
		DB.Order("name asc").Find(&categories)
		return c.JSON(categories)
	})

	app.Post("/api/categories", Protected(), func(c *fiber.Ctx) error {
		if c.Locals("role") != "admin" {
			return c.Status(403).JSON(fiber.Map{"error": "Admin required"})
		}

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
		if c.Locals("role") != "admin" {
			return c.Status(403).JSON(fiber.Map{"error": "Admin required"})
		}

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
		if c.Locals("role") != "admin" {
			return c.Status(403).JSON(fiber.Map{"error": "Admin required"})
		}

		id := c.Params("id")

		var category Category
		if err := DB.First(&category, id).Error; err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "Category not found"})
		}

		var usedCount int64
		if err := DB.Model(&Product{}).Where("category = ?", category.Name).Count(&usedCount).Error; err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to validate category usage"})
		}

		if usedCount > 0 {
			return c.Status(400).JSON(fiber.Map{"error": "Kategori masih dipakai oleh produk. Ubah kategori produk dulu sebelum menghapus."})
		}

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
		if c.Locals("role") != "admin" {
			return c.Status(403).JSON(fiber.Map{"error": "Admin required"})
		}

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
		if c.Locals("role") != "admin" {
			return c.Status(403).JSON(fiber.Map{"error": "Admin required"})
		}

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
		if c.Locals("role") != "admin" {
			return c.Status(403).JSON(fiber.Map{"error": "Admin required"})
		}

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

		layout := "2006-01-02"
		switch period {
		case "daily":
			layout = "2006-01-02"
		case "monthly":
			layout = "2006-01"
		case "yearly":
			layout = "2006"
		default:
			return c.Status(400).JSON(fiber.Map{"error": "Invalid period"})
		}

		var transactions []Transaction
		if err := DB.Where("is_voided = ?", false).Order("created_at asc").Find(&transactions).Error; err != nil {
			log.Println("Report Error:", err)
			return c.Status(500).JSON(fiber.Map{"error": "Failed to generate report"})
		}

		grouped := map[string]float64{}
		for _, transaction := range transactions {
			key := transaction.CreatedAt.Format(layout)
			grouped[key] += transaction.TotalAmount
		}

		keys := make([]string, 0, len(grouped))
		for key := range grouped {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		for _, key := range keys {
			results = append(results, struct {
				Date  string  `json:"date"`
				Total float64 `json:"total"`
			}{Date: key, Total: grouped[key]})
		}

		return c.JSON(results)
	})

	app.Get("/api/reports/daily-summary", Protected(), func(c *fiber.Ctx) error {
		dateQuery := strings.TrimSpace(c.Query("date", ""))

		var targetDate time.Time
		var err error
		if dateQuery == "" {
			now := time.Now()
			targetDate = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		} else {
			targetDate, err = time.ParseInLocation("2006-01-02", dateQuery, time.Local)
			if err != nil {
				return c.Status(400).JSON(fiber.Map{"error": "Invalid date format. Use YYYY-MM-DD"})
			}
		}

		startOfDay := targetDate
		endOfDay := startOfDay.Add(24 * time.Hour)

		var transactions []Transaction
		if err := DB.Preload("Items").Where("created_at >= ? AND created_at < ? AND is_voided = ?", startOfDay, endOfDay, false).Order("created_at asc").Find(&transactions).Error; err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to generate daily summary"})
		}

		type shiftSummary struct {
			Name             string  `json:"name"`
			TimeRange        string  `json:"time_range"`
			TransactionCount int     `json:"transaction_count"`
			Total            float64 `json:"total"`
		}

		type bestSellingProduct struct {
			Name    string  `json:"name"`
			QtySold int     `json:"qty_sold"`
			Revenue float64 `json:"revenue"`
		}

		response := fiber.Map{
			"date":              startOfDay.Format("2006-01-02"),
			"transaction_count": 0,
			"total":             0.0,
			"average_ticket":    0.0,
			"payments": fiber.Map{
				"cash":     0.0,
				"transfer": 0.0,
				"qris":     0.0,
				"other":    0.0,
			},
			"shifts": []shiftSummary{
				{Name: "Pagi", TimeRange: "06:00-12:59", TransactionCount: 0, Total: 0},
				{Name: "Siang", TimeRange: "13:00-17:59", TransactionCount: 0, Total: 0},
				{Name: "Malam", TimeRange: "18:00-05:59", TransactionCount: 0, Total: 0},
			},
			"best_selling_products": []bestSellingProduct{},
		}

		payments := response["payments"].(fiber.Map)
		shifts := response["shifts"].([]shiftSummary)
		productSales := map[string]bestSellingProduct{}

		for _, transaction := range transactions {
			response["transaction_count"] = response["transaction_count"].(int) + 1
			response["total"] = response["total"].(float64) + transaction.TotalAmount

			paymentMethod := strings.ToLower(strings.TrimSpace(transaction.PaymentMethod))
			switch paymentMethod {
			case "cash":
				payments["cash"] = payments["cash"].(float64) + transaction.TotalAmount
			case "transfer":
				payments["transfer"] = payments["transfer"].(float64) + transaction.TotalAmount
			case "qris":
				payments["qris"] = payments["qris"].(float64) + transaction.TotalAmount
			default:
				payments["other"] = payments["other"].(float64) + transaction.TotalAmount
			}

			hour := transaction.CreatedAt.Hour()
			switch {
			case hour >= 6 && hour < 13:
				shifts[0].TransactionCount++
				shifts[0].Total += transaction.TotalAmount
			case hour >= 13 && hour < 18:
				shifts[1].TransactionCount++
				shifts[1].Total += transaction.TotalAmount
			default:
				shifts[2].TransactionCount++
				shifts[2].Total += transaction.TotalAmount
			}

			for _, item := range transaction.Items {
				entry := productSales[item.ProductName]
				entry.Name = item.ProductName
				entry.QtySold += item.Qty
				entry.Revenue += float64(item.Qty) * item.Price
				productSales[item.ProductName] = entry
			}
		}

		if response["transaction_count"].(int) > 0 {
			response["average_ticket"] = response["total"].(float64) / float64(response["transaction_count"].(int))
		}

		bestProducts := make([]bestSellingProduct, 0, len(productSales))
		for _, product := range productSales {
			bestProducts = append(bestProducts, product)
		}

		sort.Slice(bestProducts, func(i, j int) bool {
			if bestProducts[i].QtySold == bestProducts[j].QtySold {
				return bestProducts[i].Revenue > bestProducts[j].Revenue
			}

			return bestProducts[i].QtySold > bestProducts[j].QtySold
		})

		if len(bestProducts) > 5 {
			bestProducts = bestProducts[:5]
		}

		response["payments"] = payments
		response["shifts"] = shifts
		response["best_selling_products"] = bestProducts

		return c.JSON(response)
	})

	// GET Activity Logs - Admin Only
	app.Get("/api/activity-logs", Protected(), func(c *fiber.Ctx) error {
		if c.Locals("role") != "admin" {
			return c.Status(403).JSON(fiber.Map{"error": "Admin required"})
		}

		page, _ := strconv.Atoi(c.Query("page", "1"))
		limit, _ := strconv.Atoi(c.Query("limit", "50"))
		if page < 1 {
			page = 1
		}
		if limit < 1 || limit > 200 {
			limit = 50
		}
		offset := (page - 1) * limit

		q := DB.Model(&ActivityLog{}).Order("created_at desc")
		if u := c.Query("username"); u != "" {
			q = q.Where("username = ?", u)
		}
		if a := c.Query("action"); a != "" {
			q = q.Where("action = ?", a)
		}
		if d := c.Query("date"); d != "" {
			q = q.Where("DATE(created_at) = ?", d)
		}

		var total int64
		q.Count(&total)

		var logs []ActivityLog
		if err := q.Limit(limit).Offset(offset).Find(&logs).Error; err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch logs"})
		}

		return c.JSON(fiber.Map{
			"data":  logs,
			"total": total,
			"page":  page,
			"limit": limit,
		})
	})

	log.Fatal(app.Listen(":" + getEnv("APP_PORT", "3000")))
}
