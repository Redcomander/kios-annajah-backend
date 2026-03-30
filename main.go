package main

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"path/filepath"
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
	Barcode        string     `gorm:"index" json:"barcode"`
	Name           string     `json:"name"`
	Price          float64    `json:"price"`
	CostPrice      float64    `json:"cost_price"`
	Stock          float64    `json:"stock"`
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
	Qty          float64    `json:"qty"`
	RemainingQty float64    `gorm:"index" json:"remaining_qty"`
	ExpiredAt    *time.Time `gorm:"index" json:"expired_at,omitempty"`
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
	ID            uint       `gorm:"primaryKey" json:"id"`
	TransactionID uint       `gorm:"index" json:"transaction_id"`
	ProductID     uint       `gorm:"index" json:"product_id"`
	ProductName   string     `json:"product_name"`
	Qty           float64    `json:"qty"`
	Price         float64    `json:"price"`
	CostPrice     float64    `json:"cost_price"`
	IsVoided      bool       `gorm:"default:false;index" json:"is_voided"`
	VoidedAt      *time.Time `json:"voided_at,omitempty"`
	VoidReason    string     `json:"void_reason,omitempty"`
}

type Transaction struct {
	ID            uint              `gorm:"primaryKey" json:"id"`
	TotalAmount   float64           `json:"total_amount"`
	PaymentMethod string            `json:"payment_method"`
	CreatedAt     time.Time         `gorm:"index" json:"created_at"`
	IsVoided      bool              `gorm:"default:false;index" json:"is_voided"`
	VoidedAt      *time.Time        `json:"voided_at,omitempty"`
	VoidReason    string            `json:"void_reason,omitempty"`
	Items         []TransactionItem `json:"items" gorm:"foreignKey:TransactionID"`
}

type DigitalTransaction struct {
	ID              uint       `gorm:"primaryKey" json:"id"`
	TransactionType string     `gorm:"index" json:"transaction_type"` // pulsa, paket_data, ewallet_topup, pln_token, bill_payment, voucher_game, emoney_topup, other
	Provider        string     `gorm:"index" json:"provider"`
	CustomerNumber  string     `gorm:"index" json:"customer_number"`
	ProductName     string     `json:"product_name"`
	BuyPrice        float64    `json:"buy_price"`
	SellPrice       float64    `json:"sell_price"`
	Fee             float64    `json:"fee"`
	AdminFee        float64    `json:"admin_fee"`
	Commission      float64    `json:"commission"`
	Profit          float64    `json:"profit"`
	Status          string     `gorm:"index" json:"status"` // pending, success, failed
	Source          string     `json:"source"`              // manual, assisted
	MitraRef        string     `gorm:"index" json:"mitra_ref"`
	FailureReason   string     `json:"failure_reason"`
	ReceiptImage    string     `json:"receipt_image"`
	OCRText         string     `gorm:"type:text" json:"ocr_text"`
	Notes           string     `json:"notes"`
	CreatedByID     uint       `json:"created_by_id"`
	CreatedBy       string     `json:"created_by"`
	UpdatedByID     uint       `json:"updated_by_id"`
	UpdatedBy       string     `json:"updated_by"`
	IsVoided        bool       `gorm:"default:false;index" json:"is_voided"`
	VoidedAt        *time.Time `json:"voided_at,omitempty"`
	VoidReason      string     `json:"void_reason,omitempty"`
	CreatedAt       time.Time  `gorm:"index" json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type ActivityLog struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    uint      `json:"user_id"`
	Username  string    `gorm:"index" json:"username"`
	Action    string    `gorm:"index" json:"action"`
	Target    string    `json:"target"`
	Details   string    `json:"details"`
	CreatedAt time.Time `gorm:"index" json:"created_at"`
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

	if err := DB.AutoMigrate(&Product{}, &ProductBatch{}, &Transaction{}, &TransactionItem{}, &DigitalTransaction{}, &Category{}, &Unit{}, &User{}, &ActivityLog{}); err != nil {
		return fmt.Errorf("auto migrate schema: %w", err)
	}

	// Barcode is optional, so old unique index must be removed to allow empty/duplicate blanks.
	_ = DB.Exec("DROP INDEX IF EXISTS idx_products_barcode").Error
	_ = DB.Migrator().CreateIndex(&Product{}, "Barcode")

	return nil
}

func parseOptionalDate(value string) (*time.Time, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, nil
	}

	// Treat zero-like placeholders as empty to avoid storing year 0001 values.
	if trimmed == "0001-01-01" || strings.HasPrefix(trimmed, "0001-01-01T") {
		return nil, nil
	}

	layouts := []string{
		"2006-01-02",
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04:05",
		"02/01/2006",
		"2/1/2006",
	}

	var parsed time.Time
	var err error
	for _, layout := range layouts {
		parsed, err = time.Parse(layout, trimmed)
		if err == nil {
			t := parsed
			if t.Year() < 1900 {
				return nil, nil
			}
			return &t, nil
		}
	}

	return nil, fmt.Errorf("invalid date format")
}

func normalizeCustomerNumber(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}

	var digits strings.Builder
	for _, char := range trimmed {
		if char >= '0' && char <= '9' {
			digits.WriteRune(char)
		}
	}

	number := digits.String()
	if number == "" {
		return ""
	}

	if strings.HasPrefix(number, "0") {
		return "62" + strings.TrimPrefix(number, "0")
	}
	if strings.HasPrefix(number, "8") {
		return "62" + number
	}

	return number
}

func isValidDigitalDestination(value string) bool {
	normalized := normalizeCustomerNumber(value)
	return len(normalized) >= 5
}

func calculateDigitalProfit(sellPrice, buyPrice, fee, adminFee, commission float64) float64 {
	return sellPrice - buyPrice - fee - adminFee + commission
}

var digitalProviderCatalog = map[string]string{
	"telkomsel": "Telkomsel",
	"indosat":   "Indosat",
	"tri":       "Tri",
	"xl":        "XL",
	"axis":      "Axis",
	"smartfren": "Smartfren",
	"byu":       "By.U",
	"pln":       "PLN",
	"bpjs":      "BPJS",
	"pdam":      "PDAM",
	"indihome":  "IndiHome",
	"telkom":    "Telkom",
	"dana":      "DANA",
	"ovo":       "OVO",
	"gopay":     "GoPay",
	"linkaja":   "LinkAja",
	"shopeepay": "ShopeePay",
	"emoney":    "e-Money",
	"emandiri":  "e-Money",
	"brizzi":    "BRIZZI",
	"flazz":     "Flazz",
	"tapcash":   "TapCash",
	"garena":    "Garena",
	"freefire":  "Free Fire",
	"mobilelegends": "Mobile Legends",
	"ml":        "Mobile Legends",
	"steam":     "Steam",
	"googleplay": "Google Play",
	"other":     "Other",
}

var digitalTransactionTypeCatalog = map[string]string{
	"pulsa":         "Pulsa",
	"paket_data":    "Paket Data",
	"ewallet_topup": "Top Up E-Wallet",
	"pln_token":     "Token PLN",
	"bill_payment":  "Tagihan",
	"voucher_game":  "Voucher/Game",
	"emoney_topup":  "Top Up E-Money",
	"other":         "Lainnya",
}

var digitalFailureReasonCatalog = map[string]string{
	"provider_timeout":     "Provider Timeout",
	"invalid_destination":  "Invalid Destination",
	"insufficient_balance": "Insufficient Balance",
	"provider_rejected":    "Provider Rejected",
	"network_error":        "Network Error",
	"duplicate_request":    "Duplicate Request",
	"customer_cancelled":   "Customer Cancelled",
	"other":                "Other",
}

func normalizeDigitalProvider(value string) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(value))
	key = strings.ReplaceAll(key, ".", "")
	key = strings.ReplaceAll(key, "-", "")
	key = strings.ReplaceAll(key, " ", "")

	canonical, ok := digitalProviderCatalog[key]
	if !ok {
		return "", false
	}

	return canonical, true
}

func normalizeFailureReasonCode(value string) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(value))
	key = strings.ReplaceAll(key, "-", "_")
	key = strings.ReplaceAll(key, " ", "_")

	_, ok := digitalFailureReasonCatalog[key]
	if !ok {
		return "", false
	}

	return key, true
}

func normalizeDigitalTransactionType(value string) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(value))
	key = strings.ReplaceAll(key, "-", "_")
	key = strings.ReplaceAll(key, " ", "_")

	_, ok := digitalTransactionTypeCatalog[key]
	if !ok {
		return "", false
	}

	return key, true
}

func formatCSVNumber(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

func buildCSVContent(headers []string, rows [][]string) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)

	if err := writer.Write(headers); err != nil {
		return nil, err
	}

	if err := writer.WriteAll(rows); err != nil {
		return nil, err
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func sendCSV(c *fiber.Ctx, filename string, headers []string, rows [][]string) error {
	content, err := buildCSVContent(headers, rows)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to generate CSV"})
	}

	c.Set("Content-Type", "text/csv; charset=utf-8")
	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	return c.Send(content)
}

func restoreTransactionItemStock(tx *gorm.DB, item TransactionItem) error {
	if err := tx.Model(&Product{}).Where("id = ?", item.ProductID).Update("stock", gorm.Expr("stock + ?", item.Qty)).Error; err != nil {
		return err
	}

	reversalBatch := ProductBatch{
		ProductID:    item.ProductID,
		Qty:          item.Qty,
		RemainingQty: item.Qty,
	}

	return tx.Create(&reversalBatch).Error
}

func syncTransactionVoidState(tx *gorm.DB, transactionID uint, fallbackReason string) error {
	var items []TransactionItem
	if err := tx.Where("transaction_id = ?", transactionID).Find(&items).Error; err != nil {
		return err
	}

	activeTotal := 0.0
	allVoided := len(items) > 0
	for _, item := range items {
		if item.IsVoided {
			continue
		}

		allVoided = false
		activeTotal += item.Price * item.Qty
	}

	updates := map[string]interface{}{
		"total_amount": activeTotal,
	}

	if allVoided {
		now := time.Now()
		updates["is_voided"] = true
		updates["voided_at"] = &now
		if strings.TrimSpace(fallbackReason) != "" {
			updates["void_reason"] = strings.TrimSpace(fallbackReason)
		}
	} else {
		updates["is_voided"] = false
		updates["voided_at"] = nil
		updates["void_reason"] = ""
	}

	return tx.Model(&Transaction{}).Where("id = ?", transactionID).Updates(updates).Error
}

func enrichProductsWithAlerts(products []Product) []Product {
	if len(products) == 0 {
		return products
	}

	now := time.Now()
	nearExpiryCutoff := now.AddDate(0, 0, nearExpiryDays)

	// Set low-stock flags in one pass
	for i := range products {
		products[i].LowStock = products[i].Stock <= lowStockThreshold
	}

	// Single batch query for earliest expiry per product — replaces N+1 loop
	productIDs := make([]uint, len(products))
	for i, p := range products {
		productIDs[i] = p.ID
	}

	type batchMin struct {
		ProductID    uint       `gorm:"column:product_id"`
		MinExpiredAt *time.Time `gorm:"column:min_expired_at"`
	}
	var batchRows []batchMin
	DB.Model(&ProductBatch{}).
		Select("product_id, MIN(expired_at) as min_expired_at").
		Where("product_id IN ? AND remaining_qty > 0 AND expired_at IS NOT NULL", productIDs).
		Group("product_id").
		Scan(&batchRows)

	expiryMap := make(map[uint]*time.Time, len(batchRows))
	for _, row := range batchRows {
		expiryMap[row.ProductID] = row.MinExpiredAt
	}

	for i := range products {
		if minExp, ok := expiryMap[products[i].ID]; ok && minExp != nil {
			products[i].NearestExpired = minExp
			products[i].NearExpiry = minExp.Before(nearExpiryCutoff) || minExp.Equal(nearExpiryCutoff)
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
	if err := ensureDir(filepath.Join(uploadsDir, "digital-receipts")); err != nil {
		log.Fatalf("Failed to create digital receipt uploads directory: %v", err)
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
		barcode := strings.TrimSpace(c.FormValue("barcode"))
		if barcode != "" {
			var count int64
			if err := DB.Model(&Product{}).Where("barcode = ? AND id <> ?", barcode, product.ID).Count(&count).Error; err == nil && count > 0 {
				return c.Status(409).JSON(fiber.Map{"error": "Barcode already exists"})
			}
		}
		product.Barcode = barcode
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
			if s, err := strconv.ParseFloat(v, 64); err == nil {
				product.Stock = s
			}
		}

		shouldUpdateExpiredAt := false
		var updatedExpiredAt *time.Time
		if form, err := c.MultipartForm(); err == nil {
			if values, ok := form.Value["expired_at"]; ok {
				shouldUpdateExpiredAt = true
				rawExpiredAt := ""
				if len(values) > 0 {
					rawExpiredAt = values[0]
				}

				parsedExpiredAt, parseErr := parseOptionalDate(rawExpiredAt)
				if parseErr != nil {
					return c.Status(400).JSON(fiber.Map{"error": "Invalid expired date format. Use YYYY-MM-DD"})
				}
				updatedExpiredAt = parsedExpiredAt
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

		if err := DB.Save(&product).Error; err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to update product"})
		}

		if shouldUpdateExpiredAt {
			if err := DB.Model(&ProductBatch{}).
				Where("product_id = ? AND remaining_qty > 0", product.ID).
				Update("expired_at", updatedExpiredAt).Error; err != nil {
				return c.Status(500).JSON(fiber.Map{"error": "Failed to update product expiry"})
			}
		}

		logActivity(c, "edit_produk", product.Name, fmt.Sprintf("harga: %.0f, stok: %.3f", product.Price, product.Stock))
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
		product.Barcode = strings.TrimSpace(c.FormValue("barcode"))
		product.Name = c.FormValue("name")
		product.Category = c.FormValue("category")
		product.Unit = c.FormValue("unit")

		if product.Barcode != "" {
			var count int64
			if err := DB.Model(&Product{}).Where("barcode = ?", product.Barcode).Count(&count).Error; err == nil && count > 0 {
				return c.Status(409).JSON(fiber.Map{"error": "Barcode already exists"})
			}
		}

		if p, err := strconv.ParseFloat(c.FormValue("price"), 64); err == nil {
			product.Price = p
		}
		if cp, err := strconv.ParseFloat(c.FormValue("cost_price"), 64); err == nil {
			product.CostPrice = cp
		}
		if s, err := strconv.ParseFloat(c.FormValue("stock"), 64); err == nil {
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
		logActivity(c, "tambah_produk", product.Name, fmt.Sprintf("harga: %.0f, stok: %.3f", product.Price, product.Stock))
		return c.JSON(product)
	})

	app.Post("/api/products/:id/restock", Protected(), func(c *fiber.Ctx) error {

		type RestockRequest struct {
			Qty       float64  `json:"qty"`
			ExpiredAt string   `json:"expired_at"`
			Price     *float64 `json:"price"`
			CostPrice *float64 `json:"cost_price"`
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

		if req.Price != nil {
			if *req.Price < 0 {
				tx.Rollback()
				return c.Status(400).JSON(fiber.Map{"error": "Harga jual tidak boleh negatif"})
			}
			if err := tx.Model(&Product{}).Where("id = ?", product.ID).Update("price", *req.Price).Error; err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{"error": "Failed to update selling price"})
			}
			product.Price = *req.Price
		}

		if req.CostPrice != nil {
			if *req.CostPrice < 0 {
				tx.Rollback()
				return c.Status(400).JSON(fiber.Map{"error": "Harga beli tidak boleh negatif"})
			}
			if err := tx.Model(&Product{}).Where("id = ?", product.ID).Update("cost_price", *req.CostPrice).Error; err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{"error": "Failed to update cost price"})
			}
			product.CostPrice = *req.CostPrice
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
		priceInfo := ""
		if req.CostPrice != nil || req.Price != nil {
			priceInfo = fmt.Sprintf(" | cost: %.0f | sell: %.0f", product.CostPrice, product.Price)
		}
		logActivity(c, "tambah_stok", product.Name, fmt.Sprintf("+%.3f unit%s", req.Qty, priceInfo))
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
		logActivity(c, "checkout", fmt.Sprintf("%d item", len(req.Items)), fmt.Sprintf("total: %.0f, metode: %s", req.Total, req.PaymentMethod))
		return c.JSON(fiber.Map{"message": "Transaction success", "id": transaction.ID})
	})

	// GET Transactions History - Protected
	app.Get("/api/transactions", Protected(), func(c *fiber.Ctx) error {
		dateFrom := strings.TrimSpace(c.Query("date_from"))
		dateTo := strings.TrimSpace(c.Query("date_to"))
		includeVoided := strings.EqualFold(strings.TrimSpace(c.Query("include_voided", "true")), "true")
		limit, _ := strconv.Atoi(c.Query("limit", "50"))
		if limit < 1 || limit > 1000 {
			limit = 50
		}

		if dateFrom != "" {
			if _, err := time.Parse("2006-01-02", dateFrom); err != nil {
				return c.Status(400).JSON(fiber.Map{"error": "Invalid date_from"})
			}
		}
		if dateTo != "" {
			if _, err := time.Parse("2006-01-02", dateTo); err != nil {
				return c.Status(400).JSON(fiber.Map{"error": "Invalid date_to"})
			}
		}

		query := DB.Preload("Items").Order("created_at desc")
		if dateFrom != "" {
			query = query.Where("DATE(created_at) >= ?", dateFrom)
		}
		if dateTo != "" {
			query = query.Where("DATE(created_at) <= ?", dateTo)
		}
		if !includeVoided {
			query = query.Where("is_voided = ?", false)
		}

		var transactions []Transaction
		if err := query.Limit(limit).Find(&transactions).Error; err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch transactions"})
		}
		return c.JSON(transactions)
	})

	app.Get("/api/exports/transactions.csv", Protected(), func(c *fiber.Ctx) error {
		dateFrom := strings.TrimSpace(c.Query("date_from"))
		dateTo := strings.TrimSpace(c.Query("date_to"))
		includeVoided := strings.EqualFold(strings.TrimSpace(c.Query("include_voided", "true")), "true")

		if dateFrom != "" {
			if _, err := time.Parse("2006-01-02", dateFrom); err != nil {
				return c.Status(400).JSON(fiber.Map{"error": "Invalid date_from"})
			}
		}
		if dateTo != "" {
			if _, err := time.Parse("2006-01-02", dateTo); err != nil {
				return c.Status(400).JSON(fiber.Map{"error": "Invalid date_to"})
			}
		}

		query := DB.Preload("Items").Model(&Transaction{}).Order("created_at desc")
		if dateFrom != "" {
			query = query.Where("DATE(created_at) >= ?", dateFrom)
		}
		if dateTo != "" {
			query = query.Where("DATE(created_at) <= ?", dateTo)
		}
		if !includeVoided {
			query = query.Where("is_voided = ?", false)
		}

		var transactions []Transaction
		if err := query.Find(&transactions).Error; err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch transactions"})
		}

		rows := make([][]string, 0, len(transactions))
		for _, transaction := range transactions {
			grossProfit := 0.0
			itemSummaries := make([]string, 0, len(transaction.Items))
			for _, item := range transaction.Items {
				if !item.IsVoided {
					grossProfit += (item.Price - item.CostPrice) * item.Qty
				}

				itemSummary := fmt.Sprintf("%s (qty %s x %s)", item.ProductName, formatCSVNumber(item.Qty), formatCSVNumber(item.Price))
				if item.IsVoided {
					itemSummary += " [VOID]"
				}
				itemSummaries = append(itemSummaries, itemSummary)
			}

			voidedAt := ""
			if transaction.VoidedAt != nil {
				voidedAt = transaction.VoidedAt.Format("2006-01-02 15:04:05")
			}

			rows = append(rows, []string{
				strconv.FormatUint(uint64(transaction.ID), 10),
				transaction.CreatedAt.Format("2006-01-02 15:04:05"),
				transaction.PaymentMethod,
				formatCSVNumber(transaction.TotalAmount),
				formatCSVNumber(grossProfit),
				strconv.FormatBool(transaction.IsVoided),
				voidedAt,
				transaction.VoidReason,
				strings.Join(itemSummaries, " | "),
			})
		}

		filename := fmt.Sprintf("transaksi_%s.csv", time.Now().Format("20060102_150405"))
		return sendCSV(c, filename, []string{"id", "created_at", "payment_method", "total_amount", "gross_profit", "is_voided", "voided_at", "void_reason", "items"}, rows)
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
		voidedAt := time.Now()
		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			reason = "Void/refund by admin"
		}

		for _, item := range transaction.Items {
			if item.IsVoided {
				continue
			}

			if err := restoreTransactionItemStock(tx, item); err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{"error": "Failed to restore stock batch"})
			}

			if err := tx.Model(&TransactionItem{}).Where("id = ?", item.ID).Updates(map[string]interface{}{
				"is_voided":   true,
				"voided_at":   &voidedAt,
				"void_reason": reason,
			}).Error; err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{"error": "Failed to mark item as voided"})
			}
		}

		if err := syncTransactionVoidState(tx, transaction.ID, reason); err != nil {
			tx.Rollback()
			return c.Status(500).JSON(fiber.Map{"error": "Failed to mark transaction as voided"})
		}

		tx.Commit()
		logActivity(c, "void_transaksi", fmt.Sprintf("trx #%d", transaction.ID), reason)
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
		voidedAt := time.Now()
		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			reason = "Refund by admin"
		}

		for _, item := range transaction.Items {
			if item.IsVoided {
				continue
			}

			if err := restoreTransactionItemStock(tx, item); err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{"error": "Failed to restore stock batch"})
			}

			if err := tx.Model(&TransactionItem{}).Where("id = ?", item.ID).Updates(map[string]interface{}{
				"is_voided":   true,
				"voided_at":   &voidedAt,
				"void_reason": reason,
			}).Error; err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{"error": "Failed to mark item as refunded"})
			}
		}

		if err := syncTransactionVoidState(tx, transaction.ID, reason); err != nil {
			tx.Rollback()
			return c.Status(500).JSON(fiber.Map{"error": "Failed to mark transaction as refunded"})
		}

		tx.Commit()
		logActivity(c, "refund_transaksi", fmt.Sprintf("trx #%d", transaction.ID), reason)
		return c.JSON(fiber.Map{"message": "Transaction refunded and stock restored"})
	})

	app.Post("/api/transactions/:id/items/:itemId/void", Protected(), func(c *fiber.Ctx) error {
		if c.Locals("role") != "admin" {
			return c.Status(403).JSON(fiber.Map{"error": "Admin required"})
		}

		transactionID := c.Params("id")
		itemID := c.Params("itemId")

		type itemVoidRequest struct {
			Reason string `json:"reason"`
		}

		var req itemVoidRequest
		_ = c.BodyParser(&req)

		var transaction Transaction
		if err := DB.Preload("Items").First(&transaction, transactionID).Error; err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "Transaction not found"})
		}

		var item TransactionItem
		if err := DB.Where("id = ? AND transaction_id = ?", itemID, transaction.ID).First(&item).Error; err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "Transaction item not found"})
		}

		if item.IsVoided {
			return c.Status(400).JSON(fiber.Map{"error": "Item already voided"})
		}

		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			reason = "Void item by admin"
		}
		voidedAt := time.Now()

		tx := DB.Begin()
		if err := restoreTransactionItemStock(tx, item); err != nil {
			tx.Rollback()
			return c.Status(500).JSON(fiber.Map{"error": "Failed to restore stock"})
		}

		if err := tx.Model(&TransactionItem{}).Where("id = ?", item.ID).Updates(map[string]interface{}{
			"is_voided":   true,
			"voided_at":   &voidedAt,
			"void_reason": reason,
		}).Error; err != nil {
			tx.Rollback()
			return c.Status(500).JSON(fiber.Map{"error": "Failed to mark item as voided"})
		}

		if err := syncTransactionVoidState(tx, transaction.ID, reason); err != nil {
			tx.Rollback()
			return c.Status(500).JSON(fiber.Map{"error": "Failed to update transaction total"})
		}

		tx.Commit()

		var updated Transaction
		if err := DB.Preload("Items").First(&updated, transaction.ID).Error; err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to reload transaction"})
		}

		logActivity(c, "void_item_transaksi", fmt.Sprintf("trx #%d", updated.ID), fmt.Sprintf("%s | %s", item.ProductName, reason))
		return c.JSON(updated)
	})

	app.Post("/api/digital-transactions/receipt", Protected(), func(c *fiber.Ctx) error {
		file, err := c.FormFile("receipt")
		if err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "receipt image is required"})
		}

		receiptDir := filepath.Join(uploadsDir, "digital-receipts")
		if err := ensureDir(receiptDir); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to prepare receipt directory"})
		}

		safeFileName := strings.ReplaceAll(filepath.Base(file.Filename), " ", "_")
		filename := fmt.Sprintf("digital_receipt_%d_%s", time.Now().UnixNano(), safeFileName)
		if err := c.SaveFile(file, filepath.Join(receiptDir, filename)); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to save receipt image"})
		}

		return c.JSON(fiber.Map{"receipt_image": "/uploads/digital-receipts/" + filename})
	})

	app.Get("/api/digital-transactions/meta", Protected(), func(c *fiber.Ctx) error {
		providers := make([]fiber.Map, 0, len(digitalProviderCatalog))
		for _, label := range []string{"Telkomsel", "Indosat", "Tri", "XL", "Axis", "Smartfren", "By.U", "PLN", "BPJS", "PDAM", "IndiHome", "Telkom", "DANA", "OVO", "GoPay", "LinkAja", "ShopeePay", "e-Money", "BRIZZI", "Flazz", "TapCash", "Garena", "Free Fire", "Mobile Legends", "Steam", "Google Play", "Other"} {
			providers = append(providers, fiber.Map{"value": label, "label": label})
		}

		transactionTypes := make([]fiber.Map, 0, len(digitalTransactionTypeCatalog))
		for _, code := range []string{"pulsa", "paket_data", "ewallet_topup", "pln_token", "bill_payment", "voucher_game", "emoney_topup", "other"} {
			transactionTypes = append(transactionTypes, fiber.Map{"value": code, "label": digitalTransactionTypeCatalog[code]})
		}

		failureReasons := make([]fiber.Map, 0, len(digitalFailureReasonCatalog))
		for _, code := range []string{"provider_timeout", "invalid_destination", "insufficient_balance", "provider_rejected", "network_error", "duplicate_request", "customer_cancelled", "other"} {
			failureReasons = append(failureReasons, fiber.Map{"value": code, "label": digitalFailureReasonCatalog[code]})
		}

		return c.JSON(fiber.Map{
			"transaction_types": transactionTypes,
			"providers":       providers,
			"failure_reasons": failureReasons,
		})
	})

	app.Post("/api/digital-transactions", Protected(), func(c *fiber.Ctx) error {
		type DigitalTransactionRequest struct {
			TransactionType string  `json:"transaction_type"`
			Provider        string  `json:"provider"`
			CustomerNumber  string  `json:"customer_number"`
			ProductName     string  `json:"product_name"`
			BuyPrice        float64 `json:"buy_price"`
			SellPrice       float64 `json:"sell_price"`
			Fee             float64 `json:"fee"`
			AdminFee        float64 `json:"admin_fee"`
			Commission      float64 `json:"commission"`
			Status          string  `json:"status"`
			Source          string  `json:"source"`
			MitraRef        string  `json:"mitra_ref"`
			FailureReason   string  `json:"failure_reason"`
			ReceiptImage    string  `json:"receipt_image"`
			OCRText         string  `json:"ocr_text"`
			Notes           string  `json:"notes"`
		}

		var req DigitalTransactionRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
		}

		typeValue, typeOK := normalizeDigitalTransactionType(req.TransactionType)
		if !typeOK {
			return c.Status(400).JSON(fiber.Map{"error": "transaction_type must be a supported Mitra product family"})
		}

		provider, providerOK := normalizeDigitalProvider(req.Provider)
		if !providerOK {
			return c.Status(400).JSON(fiber.Map{"error": "provider must be one of supported Mitra providers"})
		}

		customerNumber := normalizeCustomerNumber(req.CustomerNumber)
		if !isValidDigitalDestination(req.CustomerNumber) {
			return c.Status(400).JSON(fiber.Map{"error": "destination/customer ID is required and must be valid"})
		}

		productName := strings.TrimSpace(req.ProductName)
		if productName == "" {
			return c.Status(400).JSON(fiber.Map{"error": "product_name is required"})
		}

		mitraRef := strings.ToUpper(strings.TrimSpace(req.MitraRef))
		if mitraRef == "" {
			return c.Status(400).JSON(fiber.Map{"error": "mitra_ref is required"})
		}

		receiptImage := strings.TrimSpace(req.ReceiptImage)
		if receiptImage == "" {
			return c.Status(400).JSON(fiber.Map{"error": "receipt_image is required"})
		}

		status := strings.ToLower(strings.TrimSpace(req.Status))
		if status == "" {
			status = "pending"
		}
		if status != "pending" && status != "success" && status != "failed" {
			return c.Status(400).JSON(fiber.Map{"error": "status must be pending, success, or failed"})
		}

		source := strings.ToLower(strings.TrimSpace(req.Source))
		if source == "" {
			source = "manual"
		}
		if source != "manual" && source != "assisted" {
			return c.Status(400).JSON(fiber.Map{"error": "source must be manual or assisted"})
		}

		if req.BuyPrice <= 0 || req.SellPrice <= 0 {
			return c.Status(400).JSON(fiber.Map{"error": "buy_price and sell_price must be > 0"})
		}
		if req.Fee < 0 || req.AdminFee < 0 || req.Commission < 0 {
			return c.Status(400).JSON(fiber.Map{"error": "fee/admin_fee/commission must be >= 0"})
		}

		failureReason := ""
		if status == "failed" {
			var reasonOK bool
			failureReason, reasonOK = normalizeFailureReasonCode(req.FailureReason)
			if !reasonOK {
				return c.Status(400).JSON(fiber.Map{"error": "failure_reason must be a valid code"})
			}
		}

		var duplicateCount int64
		DB.Model(&DigitalTransaction{}).
			Where("is_voided = ? AND mitra_ref = ? AND customer_number = ? AND sell_price = ? AND created_at >= ?", false, mitraRef, customerNumber, req.SellPrice, time.Now().Add(-10*time.Minute)).
			Count(&duplicateCount)
		if duplicateCount > 0 {
			return c.Status(409).JSON(fiber.Map{"error": "Potential duplicate transaction detected (same mitra_ref/number/nominal in last 10 minutes)"})
		}

		username, _ := c.Locals("username").(string)
		userIDFloat, _ := c.Locals("user_id").(float64)
		userID := uint(userIDFloat)

		record := DigitalTransaction{
			TransactionType: typeValue,
			Provider:        provider,
			CustomerNumber:  customerNumber,
			ProductName:     productName,
			BuyPrice:        req.BuyPrice,
			SellPrice:       req.SellPrice,
			Fee:             req.Fee,
			AdminFee:        req.AdminFee,
			Commission:      req.Commission,
			Profit:          calculateDigitalProfit(req.SellPrice, req.BuyPrice, req.Fee, req.AdminFee, req.Commission),
			Status:          status,
			Source:          source,
			MitraRef:        mitraRef,
			FailureReason:   failureReason,
			ReceiptImage:    receiptImage,
			OCRText:         strings.TrimSpace(req.OCRText),
			Notes:           strings.TrimSpace(req.Notes),
			CreatedByID:     userID,
			CreatedBy:       username,
			UpdatedByID:     userID,
			UpdatedBy:       username,
		}

		if err := DB.Create(&record).Error; err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to save digital transaction"})
		}

		logActivity(c, "catat_transaksi_digital", record.CustomerNumber, fmt.Sprintf("trx_id:%d | %s %s %.0f", record.ID, record.TransactionType, record.ProductName, record.SellPrice))
		return c.JSON(record)
	})

	app.Get("/api/digital-transactions", Protected(), func(c *fiber.Ctx) error {
		limit, _ := strconv.Atoi(c.Query("limit", "300"))
		if limit < 1 || limit > 1000 {
			limit = 300
		}

		includeVoided := strings.EqualFold(strings.TrimSpace(c.Query("include_voided")), "true") || c.Query("include_voided") == "1"

		q := DB.Model(&DigitalTransaction{}).Order("created_at desc")
		if !includeVoided {
			q = q.Where("is_voided = ?", false)
		}

		if dateFrom := strings.TrimSpace(c.Query("date_from")); dateFrom != "" {
			q = q.Where("DATE(created_at) >= ?", dateFrom)
		}
		if dateTo := strings.TrimSpace(c.Query("date_to")); dateTo != "" {
			q = q.Where("DATE(created_at) <= ?", dateTo)
		}
		if status := strings.TrimSpace(c.Query("status")); status != "" {
			q = q.Where("status = ?", status)
		}
		if txType := strings.TrimSpace(c.Query("type")); txType != "" {
			q = q.Where("transaction_type = ?", txType)
		}
		if provider := strings.TrimSpace(c.Query("provider")); provider != "" {
			q = q.Where("provider LIKE ?", "%"+provider+"%")
		}
		if mitraRef := strings.TrimSpace(c.Query("mitra_ref")); mitraRef != "" {
			q = q.Where("mitra_ref LIKE ?", "%"+strings.ToUpper(mitraRef)+"%")
		}

		var rows []DigitalTransaction
		if err := q.Limit(limit).Find(&rows).Error; err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch digital transactions"})
		}

		return c.JSON(rows)
	})

	app.Get("/api/digital-transactions/:id", Protected(), func(c *fiber.Ctx) error {
		id := c.Params("id")

		var row DigitalTransaction
		if err := DB.First(&row, id).Error; err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "Digital transaction not found"})
		}

		marker := fmt.Sprintf("trx_id:%d", row.ID)
		var activities []ActivityLog
		DB.Where("action IN ? AND details LIKE ?", []string{"catat_transaksi_digital", "update_transaksi_digital", "void_transaksi_digital"}, "%"+marker+"%").
			Order("created_at asc").
			Find(&activities)

		return c.JSON(fiber.Map{
			"transaction": row,
			"timeline":    activities,
		})
	})

	app.Get("/api/exports/digital-transactions.csv", Protected(), func(c *fiber.Ctx) error {
		dateFrom := strings.TrimSpace(c.Query("date_from"))
		dateTo := strings.TrimSpace(c.Query("date_to"))
		status := strings.TrimSpace(c.Query("status"))
		txType := strings.TrimSpace(c.Query("type"))
		provider := strings.TrimSpace(c.Query("provider"))
		mitraRef := strings.TrimSpace(c.Query("mitra_ref"))
		includeVoided := strings.EqualFold(strings.TrimSpace(c.Query("include_voided")), "true") || c.Query("include_voided") == "1"

		if dateFrom != "" {
			if _, err := time.Parse("2006-01-02", dateFrom); err != nil {
				return c.Status(400).JSON(fiber.Map{"error": "Invalid date_from"})
			}
		}
		if dateTo != "" {
			if _, err := time.Parse("2006-01-02", dateTo); err != nil {
				return c.Status(400).JSON(fiber.Map{"error": "Invalid date_to"})
			}
		}

		query := DB.Model(&DigitalTransaction{}).Order("created_at desc")
		if !includeVoided {
			query = query.Where("is_voided = ?", false)
		}
		if dateFrom != "" {
			query = query.Where("DATE(created_at) >= ?", dateFrom)
		}
		if dateTo != "" {
			query = query.Where("DATE(created_at) <= ?", dateTo)
		}
		if status != "" {
			query = query.Where("status = ?", status)
		}
		if txType != "" {
			query = query.Where("transaction_type = ?", txType)
		}
		if provider != "" {
			query = query.Where("provider LIKE ?", "%"+provider+"%")
		}
		if mitraRef != "" {
			query = query.Where("mitra_ref LIKE ?", "%"+strings.ToUpper(mitraRef)+"%")
		}

		var rows []DigitalTransaction
		if err := query.Find(&rows).Error; err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to fetch digital transactions"})
		}

		csvRows := make([][]string, 0, len(rows))
		for _, row := range rows {
			voidedAt := ""
			if row.VoidedAt != nil {
				voidedAt = row.VoidedAt.Format("2006-01-02 15:04:05")
			}

			csvRows = append(csvRows, []string{
				strconv.FormatUint(uint64(row.ID), 10),
				row.CreatedAt.Format("2006-01-02 15:04:05"),
				row.TransactionType,
				row.Provider,
				row.CustomerNumber,
				row.ProductName,
				formatCSVNumber(row.BuyPrice),
				formatCSVNumber(row.SellPrice),
				formatCSVNumber(row.Fee),
				formatCSVNumber(row.AdminFee),
				formatCSVNumber(row.Commission),
				formatCSVNumber(row.Profit),
				row.Status,
				row.Source,
				row.MitraRef,
				row.FailureReason,
				row.ReceiptImage,
				strconv.FormatBool(row.IsVoided),
				voidedAt,
				row.VoidReason,
				row.CreatedBy,
				row.UpdatedBy,
				row.Notes,
			})
		}

		filename := fmt.Sprintf("transaksi_digital_%s.csv", time.Now().Format("20060102_150405"))
		return sendCSV(c, filename, []string{"id", "created_at", "transaction_type", "provider", "customer_number", "product_name", "buy_price", "sell_price", "fee", "admin_fee", "commission", "profit", "status", "source", "mitra_ref", "failure_reason", "receipt_image", "is_voided", "voided_at", "void_reason", "created_by", "updated_by", "notes"}, csvRows)
	})

	app.Patch("/api/digital-transactions/:id/status", Protected(), func(c *fiber.Ctx) error {
		id := c.Params("id")

		type updateStatusRequest struct {
			Status        string `json:"status"`
			Notes         string `json:"notes"`
			FailureReason string `json:"failure_reason"`
		}

		var req updateStatusRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
		}

		status := strings.ToLower(strings.TrimSpace(req.Status))
		if status != "pending" && status != "success" && status != "failed" {
			return c.Status(400).JSON(fiber.Map{"error": "status must be pending, success, or failed"})
		}

		var row DigitalTransaction
		if err := DB.First(&row, id).Error; err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "Digital transaction not found"})
		}
		if row.IsVoided {
			return c.Status(409).JSON(fiber.Map{"error": "Cannot update status for voided transaction"})
		}

		failureReason := ""
		if status == "failed" {
			var reasonOK bool
			failureReason, reasonOK = normalizeFailureReasonCode(req.FailureReason)
			if !reasonOK {
				return c.Status(400).JSON(fiber.Map{"error": "failure_reason must be a valid code"})
			}
		}

		username, _ := c.Locals("username").(string)
		userIDFloat, _ := c.Locals("user_id").(float64)

		updates := map[string]interface{}{
			"status":         status,
			"updated_by_id":  uint(userIDFloat),
			"updated_by":     username,
			"failure_reason": "",
		}
		if notes := strings.TrimSpace(req.Notes); notes != "" {
			updates["notes"] = notes
		}
		if status == "failed" {
			updates["failure_reason"] = failureReason
		}

		if err := DB.Model(&DigitalTransaction{}).Where("id = ?", id).Updates(updates).Error; err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to update status"})
		}

		if err := DB.First(&row, id).Error; err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "Digital transaction not found"})
		}

		logActivity(c, "update_transaksi_digital", row.CustomerNumber, fmt.Sprintf("trx_id:%d | status: %s", row.ID, row.Status))
		return c.JSON(row)
	})

	app.Patch("/api/digital-transactions/:id/void", Protected(), func(c *fiber.Ctx) error {
		id := c.Params("id")

		type voidRequest struct {
			Reason string `json:"reason"`
		}

		var req voidRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
		}

		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			return c.Status(400).JSON(fiber.Map{"error": "reason is required"})
		}

		var row DigitalTransaction
		if err := DB.First(&row, id).Error; err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "Digital transaction not found"})
		}
		if row.IsVoided {
			return c.Status(409).JSON(fiber.Map{"error": "Transaction already voided"})
		}

		now := time.Now()
		username, _ := c.Locals("username").(string)
		userIDFloat, _ := c.Locals("user_id").(float64)

		if err := DB.Model(&DigitalTransaction{}).Where("id = ?", id).Updates(map[string]interface{}{
			"is_voided":     true,
			"voided_at":     &now,
			"void_reason":   reason,
			"updated_by_id": uint(userIDFloat),
			"updated_by":    username,
		}).Error; err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Failed to void transaction"})
		}

		if err := DB.First(&row, id).Error; err != nil {
			return c.Status(404).JSON(fiber.Map{"error": "Digital transaction not found"})
		}

		logActivity(c, "void_transaksi_digital", row.CustomerNumber, fmt.Sprintf("trx_id:%d | %s", row.ID, reason))
		return c.JSON(row)
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

		// Use SQL GROUP BY — avoids loading all transactions into memory
		var dateExpr string
		if resolveDatabaseDriver() == "sqlite" {
			switch period {
			case "daily":
				dateExpr = "strftime('%Y-%m-%d', created_at)"
			case "monthly":
				dateExpr = "strftime('%Y-%m', created_at)"
			case "yearly":
				dateExpr = "strftime('%Y', created_at)"
			default:
				return c.Status(400).JSON(fiber.Map{"error": "Invalid period"})
			}
		} else {
			switch period {
			case "daily":
				dateExpr = "TO_CHAR(created_at, 'YYYY-MM-DD')"
			case "monthly":
				dateExpr = "TO_CHAR(created_at, 'YYYY-MM')"
			case "yearly":
				dateExpr = "TO_CHAR(created_at, 'YYYY')"
			default:
				return c.Status(400).JSON(fiber.Map{"error": "Invalid period"})
			}
		}

		type chartPoint struct {
			Date  string  `gorm:"column:date" json:"date"`
			Total float64 `gorm:"column:total" json:"total"`
		}
		var results []chartPoint
		if err := DB.Model(&Transaction{}).
			Where("is_voided = ?", false).
			Select(fmt.Sprintf("%s as date, SUM(total_amount) as total", dateExpr)).
			Group(dateExpr).
			Order(dateExpr + " asc").
			Scan(&results).Error; err != nil {
			log.Println("Report Error:", err)
			return c.Status(500).JSON(fiber.Map{"error": "Failed to generate report"})
		}

		if results == nil {
			results = []chartPoint{}
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

		// Load transactions without items — items are aggregated via a separate SQL query below
		var transactions []Transaction
		if err := DB.Where("created_at >= ? AND created_at < ? AND is_voided = ?", startOfDay, endOfDay, false).Order("created_at asc").Find(&transactions).Error; err != nil {
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
			QtySold float64 `json:"qty_sold"`
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
		}

		if response["transaction_count"].(int) > 0 {
			response["average_ticket"] = response["total"].(float64) / float64(response["transaction_count"].(int))
		}

		// Best-selling products via SQL GROUP BY — no in-memory aggregation needed
		var bestProducts []bestSellingProduct
		DB.Model(&TransactionItem{}).
			Joins("JOIN transactions ON transactions.id = transaction_items.transaction_id").
			Where("transactions.created_at >= ? AND transactions.created_at < ? AND transactions.is_voided = ? AND transaction_items.is_voided = ?",
				startOfDay, endOfDay, false, false).
			Select("transaction_items.product_name as name, SUM(transaction_items.qty) as qty_sold, SUM(transaction_items.qty * transaction_items.price) as revenue").
			Group("transaction_items.product_name").
			Order("qty_sold desc, revenue desc").
			Limit(5).
			Scan(&bestProducts)
		if bestProducts == nil {
			bestProducts = []bestSellingProduct{}
		}

		response["payments"] = payments
		response["shifts"] = shifts
		response["best_selling_products"] = bestProducts

		return c.JSON(response)
	})
	// DIGITAL TRANSACTION REPORT
	app.Get("/api/reports/digital-summary", Protected(), func(c *fiber.Ctx) error {
		now := time.Now()
		defaultFrom := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).Format("2006-01-02")
		defaultTo := now.Format("2006-01-02")
		dateFrom := strings.TrimSpace(c.Query("date_from", defaultFrom))
		dateTo := strings.TrimSpace(c.Query("date_to", defaultTo))

		if _, err := time.Parse("2006-01-02", dateFrom); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid date_from"})
		}
		if _, err := time.Parse("2006-01-02", dateTo); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid date_to"})
		}

		type dStats struct {
			TotalCount   int64   `json:"total_count"`
			SuccessCount int64   `json:"success_count"`
			FailedCount  int64   `json:"failed_count"`
			PendingCount int64   `json:"pending_count"`
			TotalOmzet   float64 `json:"total_omzet"`
			TotalProfit  float64 `json:"total_profit"`
		}
		var stats dStats
		DB.Model(&DigitalTransaction{}).
			Where("DATE(created_at) >= ? AND DATE(created_at) <= ? AND is_voided = ?", dateFrom, dateTo, false).
			Select("COUNT(*) as total_count, " +
				"SUM(CASE WHEN status='success' THEN 1 ELSE 0 END) as success_count, " +
				"SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) as failed_count, " +
				"SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) as pending_count, " +
				"SUM(CASE WHEN status='success' THEN sell_price ELSE 0 END) as total_omzet, " +
				"SUM(CASE WHEN status='success' THEN profit ELSE 0 END) as total_profit").
			Scan(&stats)

		type dTypeBreakdown struct {
			Type   string  `json:"type"`
			Count  int64   `json:"count"`
			Omzet  float64 `json:"omzet"`
			Profit float64 `json:"profit"`
		}
		byType := []dTypeBreakdown{}
		DB.Model(&DigitalTransaction{}).
			Where("DATE(created_at) >= ? AND DATE(created_at) <= ? AND is_voided = ?", dateFrom, dateTo, false).
			Select("transaction_type as type, COUNT(*) as count, " +
				"SUM(CASE WHEN status='success' THEN sell_price ELSE 0 END) as omzet, " +
				"SUM(CASE WHEN status='success' THEN profit ELSE 0 END) as profit").
			Group("transaction_type").
			Scan(&byType)

		type dProviderBreakdown struct {
			Provider string  `json:"provider"`
			Count    int64   `json:"count"`
			Omzet    float64 `json:"omzet"`
			Profit   float64 `json:"profit"`
		}
		byProvider := []dProviderBreakdown{}
		DB.Model(&DigitalTransaction{}).
			Where("DATE(created_at) >= ? AND DATE(created_at) <= ? AND TRIM(provider) != '' AND is_voided = ?", dateFrom, dateTo, false).
			Select("provider, COUNT(*) as count, " +
				"SUM(CASE WHEN status='success' THEN sell_price ELSE 0 END) as omzet, " +
				"SUM(CASE WHEN status='success' THEN profit ELSE 0 END) as profit").
			Group("provider").
			Order("count desc").
			Scan(&byProvider)

		type dDailyPoint struct {
			Date   string  `json:"date"`
			Count  int64   `json:"count"`
			Omzet  float64 `json:"omzet"`
			Profit float64 `json:"profit"`
		}
		daily := []dDailyPoint{}
		DB.Model(&DigitalTransaction{}).
			Where("DATE(created_at) >= ? AND DATE(created_at) <= ? AND is_voided = ?", dateFrom, dateTo, false).
			Select("DATE(created_at) as date, COUNT(*) as count, " +
				"SUM(CASE WHEN status='success' THEN sell_price ELSE 0 END) as omzet, " +
				"SUM(CASE WHEN status='success' THEN profit ELSE 0 END) as profit").
			Group("DATE(created_at)").
			Order("date asc").
			Scan(&daily)

		return c.JSON(fiber.Map{
			"date_from":     dateFrom,
			"date_to":       dateTo,
			"total_count":   stats.TotalCount,
			"success_count": stats.SuccessCount,
			"failed_count":  stats.FailedCount,
			"pending_count": stats.PendingCount,
			"total_omzet":   stats.TotalOmzet,
			"total_profit":  stats.TotalProfit,
			"by_type":       byType,
			"by_provider":   byProvider,
			"daily":         daily,
		})
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
