package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"log"
	"net/http"
	"os"
	"strconv"
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
	Transid string `json:"order_uuid"`
	Amount  int    `json:"amount"`
	Url     string `json:"acquiring_page"`
}

type WataWebhookRequestData struct {
	Transid string `json:"transaction_uuid"`
	Amount  int    `json:"amount"`
	Status  string `json:"status"`
	Orderid string `json:"order_id"`
	Date    string `json:"paid_date_msk"`
	Hash    string `json:"hash"`
}

func payment(w http.ResponseWriter, r *http.Request) {
	var err error
	invid := r.FormValue("invoice_id")
	invoice_id, err := strconv.ParseInt(invid, 10, 64)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Incorrect id", http.StatusBadRequest)
		return
	}
	amt := r.FormValue("amount")
	amount, err := strconv.ParseFloat(amt, 32)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Incorrect amount", http.StatusBadRequest)
		return
	}
	payment_id := r.FormValue("payment_id")
	return_url := r.FormValue("return_url")
	description := r.FormValue("description")
	currency := r.FormValue("currency")
	InsertQuery(connPool, invoice_id, float32(amount), currency, "wait")
	if payment_id == "20122" {
		client := &http.Client{}
		url := "https://acquiring.foreignpay.ru/webhook/partner_sbp/transaction"
		amount /= 1 - commissions["20122"]
		data := []byte(fmt.Sprintf(`{"amount": %.2f, "description": %s, "success_url": %s, "fail_url": %s, "merchant_order_id": %s }`, amount, description, return_url, return_url, invoice_id))
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
		if err != nil {
			fmt.Println(err)
			http.Error(w, "Wata error", http.StatusBadRequest)
			return
		}
		req.Header.Add("Authorization", os.Getenv("wata_sbp_token"))
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println(err)
			http.Error(w, "Wata error", http.StatusBadRequest)
			return
		}
		defer resp.Body.Close()
		var respdata WataRequestData
		err = json.NewDecoder(resp.Body).Decode(&respdata)
		if err != nil {
			fmt.Println(err)
			http.Error(w, "Wata error", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, respdata.Url, http.StatusSeeOther)
	}
}

func webhookwata(w http.ResponseWriter, r *http.Request) {
	var respdata WataWebhookRequestData
	err := json.NewDecoder(r.Body).Decode(&respdata)
	if err != nil {
		http.Error(w, "Webhook error", http.StatusBadRequest)
		return
	}
	if r.RemoteAddr != "62.76.102.182" {
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
	if respdata.Status == "Paid" {
		invoice_id, err := strconv.ParseInt(respdata.Orderid, 10, 64)
		if err != nil {
			http.Error(w, "Incorrect id", http.StatusBadRequest)
			return
		}
		UpdateStatusQuery(connPool, invoice_id, "paid")
		amount, currency := SelectWebhookQuery(connPool, invoice_id)
		hash := []byte(fmt.Sprintf("amount:%.2f;currency:%s;invoice_id:%d;status:%s;", amount, currency, invoice_id, "paid"))
		mac := hmac.New(sha256.New, []byte(os.Getenv("HASH_KEY")))
		mac.Write(hash)
		signature := mac.Sum(nil)
		url := "https://digiseller.market/callback/api"
		data := []byte(fmt.Sprintf(`{"invoice_id": %d,"amount": %.2f, "currency": %s, "status": %s, "signature": %s }`, invoice_id, amount, currency, "paid", signature))
		req, err := http.NewRequest("GET", url, bytes.NewBuffer(data))
		if err != nil {
			http.Error(w, "Digiseller error", http.StatusBadRequest)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "Digiseller error", http.StatusBadRequest)
			return
		}
		defer resp.Body.Close()
	}
}
