package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func Config() *pgxpool.Config {
	const defaultMaxConns = int32(4)
	const defaultMinConns = int32(0)
	const defaultMaxConnLifetime = time.Hour
	const defaultMaxConnIdleTime = time.Minute * 30
	const defaultHealthCheckPeriod = time.Minute
	const defaultConnectTimeout = time.Second * 5

	dbConfig, err := pgxpool.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal("Failed to create a config, error: ", err)
	}

	dbConfig.MaxConns = defaultMaxConns
	dbConfig.MinConns = defaultMinConns
	dbConfig.MaxConnLifetime = defaultMaxConnLifetime
	dbConfig.MaxConnIdleTime = defaultMaxConnIdleTime
	dbConfig.HealthCheckPeriod = defaultHealthCheckPeriod
	dbConfig.ConnConfig.ConnectTimeout = defaultConnectTimeout

	dbConfig.BeforeAcquire = func(ctx context.Context, c *pgx.Conn) bool {
		log.Println("Before acquiring the connection pool to the database!!")
		return true
	}

	dbConfig.AfterRelease = func(c *pgx.Conn) bool {
		log.Println("After releasing the connection pool to the database!!")
		return true
	}

	dbConfig.BeforeClose = func(c *pgx.Conn) {
		log.Println("Closed the connection pool to the database!!")
	}

	return dbConfig
}

func CreateTableQuery(p *pgxpool.Pool) {
	_, err := p.Exec(context.Background(), "CREATE TABLE IF NOT EXISTS orders (invoice_id BIGINT PRIMARY KEY,amount NUMERIC(10, 2) NOT NULL,currency VARCHAR(3) NOT NULL, status VARCHAR(10) NOT NULL);")
	if err != nil {
		log.Fatal("Error while creating the table")
	}
}

func InsertQuery(p *pgxpool.Pool, invoice_id int64, amount float32, currency string, status string) {
	_, err := p.Exec(context.Background(), "INSERT INTO orders(invoice_id, amount, currency, status) values($1, $2, $3, $4)", invoice_id, amount, currency, status)
	if err != nil {
		log.Fatal("Error while inserting value into the table")
	}
}

func UpdateStatusQuery(p *pgxpool.Pool, invoice_id int64, status string) {
	_, err := p.Exec(context.Background(), "UPDATE orders SET status = $2 WHERE invoice_id = $1", invoice_id, status)
	if err != nil {
		log.Fatal("Error while inserting value into the table")
	}
}

func SelectWebhookQuery(p *pgxpool.Pool, invoice_id int64) (float32, string) {
	var amount float32
	var currency string
	err := p.QueryRow(context.Background(), "select amount, currency from orders where invoice_id=$1", invoice_id).Scan(&amount, &currency)
	if err != nil {
		log.Fatal("Error while selecting value from the table")
	}
	return amount, currency
}

func SelectStatusQuery(p *pgxpool.Pool, invoice_id int64) string {
	var status string
	err := p.QueryRow(context.Background(), "select status from orders where invoice_id=$1", invoice_id).Scan(&status)
	if err != nil {
		log.Fatal("Error while selecting value from the table")
	}
	return status
}

var commissions map[string]float64
var connPool *pgxpool.Pool

func main() {
	commissions = make(map[string]float64)
	commissions["20122"] = 11.00
	var err error
	connPool, err = pgxpool.NewWithConfig(context.Background(), Config())
	if err != nil {
		log.Fatal("Error while creating connection to the database!!")
	}
	connection, err := connPool.Acquire(context.Background())
	if err != nil {
		log.Fatal("Error while acquiring connection from the database pool!!")
	}
	defer connection.Release()
	err = connection.Ping(context.Background())
	if err != nil {
		log.Fatal("Could not ping database")
	}

	CreateTableQuery(connPool)
	defer connPool.Close()
	http.HandleFunc("/payment/", payment)
	http.HandleFunc("/webhookwata/", webhookwata)
	log.Fatal(http.ListenAndServe("0.0.0.0"+":"+os.Getenv("PORT"), nil))
}

type WataRequestData struct {
	Transid string  `json:"order_uuid"`
	Amount  float32 `json:"amount"`
	Url     string  `json:"acquiring_page"`
}

type WataWebhookRequestData struct {
	Transid string `json:"transaction_uuid"`
	Amount  int    `json:"amount"`
	Status  string `json:"status"`
	Orderid string `json:"order_id"`
	Date    string `json:"paid_date_msk"`
	Hash    string `json:"hash"`
}

type WataPaymentRequest struct {
	Amount          float32 `json:"amount"`
	Description     string  `json:"description"`
	SuccessURL      string  `json:"success_url"`
	FailURL         string  `json:"fail_url"`
	MerchantOrderID string  `json:"merchant_order_id"`
}

type CryptomusPaymentRequest struct {
	Amount          string `json:"amount"`
	Currency        string `json:"currency"`
	MerchantOrderID string `json:"order_id"`
	Network         string `json:"network"`
	SuccessURL      string `json:"url_success"`
	CallbackURL     string `json:"url_callback"`
	ToCurrency      string `json:"to_currency"`
}

func payment(w http.ResponseWriter, r *http.Request) {
	var err error
	err = r.ParseForm()
	if err != nil {
		http.Error(w, "Incorrect data", http.StatusBadRequest)
		return
	}
	invoice_id, err := strconv.ParseInt(r.Form["invoice_id"][0], 10, 64)
	if err != nil {
		http.Error(w, "Incorrect id", http.StatusBadRequest)
		return
	}
	amount, err := strconv.ParseFloat(r.Form["amount"][0], 32)
	if err != nil {
		http.Error(w, "Incorrect amount", http.StatusBadRequest)
		return
	}
	payment_id := r.Form["payment_id"][0]
	return_url := r.Form["return_url"][0]
	description := r.Form["description"][0]
	currency := r.Form["currency"][0]
	InsertQuery(connPool, invoice_id, float32(amount), currency, "wait")
	client := &http.Client{}
	if payment_id == "20122" {
		urlwata := "https://acquiring.foreignpay.ru/webhook/partner_sbp/transaction"
		paymentData := WataPaymentRequest{
			Amount:          float32(amount),
			Description:     description,
			SuccessURL:      return_url,
			FailURL:         return_url,
			MerchantOrderID: strconv.Itoa(int(invoice_id)),
		}
		data, err := json.Marshal(paymentData)
		if err != nil {
			log.Fatal("Error marshaling JSON:", err)
		}
		req, err := http.NewRequest("POST", urlwata, bytes.NewBuffer(data))
		if err != nil {
			http.Error(w, "Wata error", http.StatusBadRequest)
			return
		}
		req.Header.Add("Authorization", "Bearer "+os.Getenv("wata_sbp_token"))
		req.Header.Add("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "Wata error", http.StatusBadRequest)
			return
		}
		defer resp.Body.Close()
		var respdata WataRequestData
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, "Wata error", http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(body, &respdata); err != nil {
			http.Error(w, "Wata error", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, respdata.Url, http.StatusSeeOther)
	} else {
		to_currency := ""
		network := ""
		if payment_id == "20064" {
			to_currency = "USDT"
			network = "ton"
		} else if payment_id == "20066" {
			to_currency = "USDT"
			network = "tron"
		} else if payment_id == "20067" {
			to_currency = "USDT"
			network = "bsc"
		} else if payment_id == "20068" {
			to_currency = "BTC"
			network = "btc"
		} else if payment_id == "20069" {
			to_currency = "ETH"
			network = "bsc"
		} else if payment_id == "20070" {
			to_currency = "ETH"
			network = "eth"
		}
		urlcrypto := "https://api.cryptomus.com/v1/payment"
		var paymentData CryptomusPaymentRequest
		if len(to_currency) != 0 && len(network) != 0 {
			paymentData = CryptomusPaymentRequest{
				Amount:          fmt.Sprintf("%f", amount),
				Currency:        currency,
				MerchantOrderID: strconv.Itoa(int(invoice_id)),
				Network:         network,
				SuccessURL:      return_url,
				CallbackURL:     os.Getenv("URL") + "cryptomus/",
				ToCurrency:      to_currency,
			}
		} else {
			paymentData = CryptomusPaymentRequest{
				Amount:          fmt.Sprintf("%f", amount),
				Currency:        currency,
				MerchantOrderID: strconv.Itoa(int(invoice_id)),
				SuccessURL:      return_url,
				CallbackURL:     os.Getenv("URL") + "cryptomus/",
			}
		}
		data, err := json.Marshal(paymentData)
		if err != nil {
			log.Fatal("Error marshaling JSON:", err)
		}
		req, err := http.NewRequest("POST", urlcrypto, bytes.NewBuffer(data))
		if err != nil {
			http.Error(w, "Cryptomus error", http.StatusBadRequest)
			return
		}
		base64Data := base64.StdEncoding.EncodeToString(data)
		concatData := base64Data + os.Getenv("cryptomus_api")
		hasher := md5.New()
		hasher.Write([]byte(concatData))
		sign := hex.EncodeToString(hasher.Sum(nil))
		req.Header.Add("merchant", os.Getenv("cryptomus_merchant"))
		req.Header.Add("sign", sign)
		req.Header.Add("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "Cryptomus error", http.StatusBadRequest)
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, "Cryptomus error", http.StatusBadRequest)
			return
		}
		fmt.Println(len(return_url))
		fmt.Print(resp.Status)
		fmt.Println(string(body))
	}
}

func webhookwata(w http.ResponseWriter, r *http.Request) {
	var respdata WataWebhookRequestData
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Incorrect webhook", http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &respdata); err != nil {
		http.Error(w, "Incorrect webhook", http.StatusBadRequest)
		return
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "Unable to parse RemoteAddr", http.StatusBadRequest)
		return
	}
	if ip != "62.76.102.182" {
		http.Error(w, "Incorrect IP", http.StatusBadRequest)
		return
	}
	hash := []byte(fmt.Sprintf("%s%s", respdata.Transid, os.Getenv("wata_sbp_token")))
	mac := hmac.New(sha256.New, []byte(os.Getenv("HASH_KEY")))
	mac.Write(hash)
	signature := mac.Sum(nil)
	if !hmac.Equal([]byte(respdata.Hash), signature) {
		http.Error(w, "Incorrect signature", http.StatusBadRequest)
		return
	}
	client := &http.Client{}
	status := ""
	if respdata.Status == "Paid" {
		status = "paid"
	} else if respdata.Status == "Pending" || respdata.Status == "Created" {
		status = "wait"
	} else if respdata.Status == "Failed" || respdata.Status == "Expired" {
		status = "canceled"
	} else if respdata.Status == "Refunded" || respdata.Status == "Chargebacked" {
		status = "refunded"
	} else {
		http.Error(w, "Incorrect status", http.StatusBadRequest)
		return
	}
	invoice_id, err := strconv.ParseInt(respdata.Orderid, 10, 64)
	if err != nil {
		http.Error(w, "Incorrect id", http.StatusBadRequest)
		return
	}
	UpdateStatusQuery(connPool, invoice_id, status)
	amount, currency := SelectWebhookQuery(connPool, invoice_id)
	hash = []byte(fmt.Sprintf("amount:%.2f;currency:%s;invoice_id:%d;status:%s;", amount, currency, invoice_id, status))
	mac = hmac.New(sha256.New, []byte(os.Getenv("HASH_KEY")))
	mac.Write(hash)
	signature = mac.Sum(nil)
	apiUrl := "https://digiseller.market"
	resource := "/callback/api"
	data := url.Values{}
	data.Set("invoice_id", strconv.FormatInt(invoice_id, 10))
	data.Set("amount", fmt.Sprintf("%f", amount))
	data.Set("currency", currency)
	data.Set("status", status)
	data.Set("signature", string(signature))
	u, err := url.ParseRequestURI(apiUrl)
	if err != nil {
		http.Error(w, "Incorrect url", http.StatusBadRequest)
		return
	}
	u.Path = resource
	urlStr := u.String()
	req, err := http.NewRequest("GET", urlStr, strings.NewReader(data.Encode()))
	if err != nil {
		http.Error(w, "Digiseller error", http.StatusBadRequest)
		return
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Digiseller error", http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()
}
