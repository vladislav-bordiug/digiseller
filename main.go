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
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func Config() *pgxpool.Config {
	// const defaultMaxConns = int32(4)
	// const defaultMinConns = int32(0)
	const defaultMaxConnLifetime = time.Hour
	const defaultMaxConnIdleTime = time.Minute * 30
	const defaultHealthCheckPeriod = time.Minute
	const defaultConnectTimeout = time.Second * 5

	dbConfig, err := pgxpool.ParseConfig(os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal("Failed to create a config, error: ", err)
	}

	// dbConfig.MaxConns = defaultMaxConns
	// dbConfig.MinConns = defaultMinConns
	dbConfig.MaxConnLifetime = defaultMaxConnLifetime
	dbConfig.MaxConnIdleTime = defaultMaxConnIdleTime
	dbConfig.HealthCheckPeriod = defaultHealthCheckPeriod
	dbConfig.ConnConfig.ConnectTimeout = defaultConnectTimeout

	/*
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
	*/

	return dbConfig
}

func CreateTableQuery(p *pgxpool.Pool) error {
	_, err := p.Exec(context.Background(), "CREATE TABLE IF NOT EXISTS orders (invoice_id BIGINT PRIMARY KEY,amount NUMERIC(10, 2) NOT NULL,currency VARCHAR(3) NOT NULL, status VARCHAR(10) NOT NULL);")
	if err != nil {
		return err
	}
	return nil
}

func InsertQuery(p *pgxpool.Pool, invoice_id int64, amount float32, currency string, status string) error {
	_, err := p.Exec(context.Background(), "INSERT INTO orders(invoice_id, amount, currency, status) values($1, $2, $3, $4)", invoice_id, amount, currency, status)
	if err != nil {
		return err
	}
	return nil
}

func UpdateStatusQuery(p *pgxpool.Pool, invoice_id int64, status string) error {
	_, err := p.Exec(context.Background(), "UPDATE orders SET status = $2 WHERE invoice_id = $1", invoice_id, status)
	if err != nil {
		return err
	}
	return nil
}

func SelectWebhookQuery(p *pgxpool.Pool, invoice_id int64) (float32, string, error) {
	var amount float32
	var currency string
	err := p.QueryRow(context.Background(), "select amount, currency from orders where invoice_id=$1", invoice_id).Scan(&amount, &currency)
	if err != nil {
		return 0.0, "RUB", err
	}
	return amount, currency, nil
}

func SelectStatusQuery(p *pgxpool.Pool, invoice_id int64) string {
	var status string
	err := p.QueryRow(context.Background(), "select status from orders where invoice_id=$1", invoice_id).Scan(&status)
	if err != nil {
		return "wait"
	}
	return status
}

var connPool *pgxpool.Pool

func main() {
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
	err = CreateTableQuery(connPool)
	if err != nil {
		log.Fatal(err)
	}
	defer connPool.Close()
	http.HandleFunc("/payment/", payment)
	http.HandleFunc("/status/", status)
	http.HandleFunc("/webhookwata/", webhookwata)
	http.HandleFunc("/webhookcryptomus/", webhookcryptomus)
	log.Fatal(http.ListenAndServe("0.0.0.0"+":"+os.Getenv("PORT"), nil))
}

type WataRequestData struct {
	Transid string  `json:"order_uuid"`
	Amount  float32 `json:"amount"`
	Url     string  `json:"acquiring_page"`
}

type WataWebhookRequestData struct {
	Transid string  `json:"order_uuid"`
	Amount  float32 `json:"amount"`
	Status  string  `json:"status"`
	Orderid string  `json:"order_id"`
	Date    string  `json:"paid_date_msk"`
	Hash    string  `json:"hash"`
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

type CryptomusRequestData struct {
	State  int                 `json:"state"`
	Result CryptomusResultData `json:"result"`
}

type CryptomusResultData struct {
	Transid string `json:"order_id"`
	Amount  string `json:"amount"`
	Url     string `json:"url"`
}

type CryptomusError struct {
	State   int    `json:"state"`
	Message string `json:"message"`
}

type DigisellerStatus struct {
	Transid   string `json:"invoice_id"`
	Sellerid  string `json:"seller_id"`
	Amount    string `json:"amount"`
	Currency  string `json:"currency"`
	Signature string `json:"signature"`
}

type DigisellerStatusAnswer struct {
	Transid   string `json:"invoice_id"`
	Amount    string `json:"amount"`
	Currency  string `json:"currency"`
	Status    string `json:"status"`
	Signature string `json:"signature"`
}

type CryptomusWebhookRequestData struct {
	Type                    string  `json:"type"`
	Uuid                    string  `json:"uuid"`
	OrderID                 string  `json:"order_id"`
	Amount                  string  `json:"amount"`
	PaymentAmount           string  `json:"payment_amount"`
	PaymentAmountUSD        string  `json:"payment_amount_usd"`
	MerchantAmount          string  `json:"merchant_amount"`
	Commission              string  `json:"commission"`
	IsFinal                 bool    `json:"is_final"`
	Status                  string  `json:"status"`
	From                    *string `json:"from"`
	WalletAddressUUID       *string `json:"wallet_address_uuid"`
	Network                 *string `json:"network"`
	Currency                *string `json:"currency"`
	PayerCurrency           *string `json:"payer_currency"`
	PayerAmount             *string `json:"payer_amount"`
	PayerAmountExchangeRate *string `json:"payer_amount_exchange_rate"`
	AdditionalData          *string `json:"additional_data"`
	TransferID              *string `json:"transfer_id"`
	Txid                    *string `json:"txid"`
}

type CryptomusWebhookRequestSignature struct {
	Signature string `json:"sign"`
}

func md5hash(data []byte) string {
	base64Data := base64.StdEncoding.EncodeToString(data)
	concatData := base64Data + os.Getenv("cryptomus_api")
	hasher := md5.New()
	hasher.Write([]byte(concatData))
	sign := hex.EncodeToString(hasher.Sum(nil))
	return sign
}

func sha256hmac(data []byte) []byte {
	mac := hmac.New(sha256.New, []byte(os.Getenv("HASH_KEY")))
	mac.Write(data)
	signature := mac.Sum(nil)
	return signature
}

func makesha256(data []byte) string {
	h := sha256.New()
	h.Write(data)
	signature := hex.EncodeToString(h.Sum(nil))
	return signature
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
	returnurl := r.Form["return_url"][0]
	return_url, err := url.QueryUnescape(returnurl)
	if err != nil {
		http.Error(w, "Error in encoding returning url:", http.StatusBadRequest)
		return
	}
	description := r.Form["description"][0]
	currency := r.Form["currency"][0]
	err = InsertQuery(connPool, invoice_id, float32(amount), currency, "wait")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
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
			http.Error(w, "Error marshaling JSON:", http.StatusBadRequest)
			return
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
		if len(respdata.Url) == 0 {
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
				CallbackURL:     os.Getenv("URL") + "webhookcryptomus/",
				ToCurrency:      to_currency,
			}
		} else {
			paymentData = CryptomusPaymentRequest{
				Amount:          fmt.Sprintf("%f", amount),
				Currency:        currency,
				MerchantOrderID: strconv.Itoa(int(invoice_id)),
				SuccessURL:      return_url,
				CallbackURL:     os.Getenv("URL") + "webhookcryptomus/",
			}
		}
		data, err := json.Marshal(paymentData)
		if err != nil {
			http.Error(w, "Error marshaling JSON:", http.StatusBadRequest)
			return
		}
		req, err := http.NewRequest("POST", urlcrypto, bytes.NewBuffer(data))
		if err != nil {
			http.Error(w, "Cryptomus error", http.StatusBadRequest)
			return
		}
		sign := md5hash(data)
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
		var respdata CryptomusRequestData
		if err := json.Unmarshal(body, &respdata); err != nil {
			http.Error(w, "Cryptomus error", http.StatusBadRequest)
			return
		}
		if len(respdata.Result.Url) == 0 {
			var respdata CryptomusError
			if err := json.Unmarshal(body, &respdata); err != nil {
				http.Error(w, "Cryptomus error", http.StatusBadRequest)
				return
			}
			http.Error(w, respdata.Message, http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, respdata.Result.Url, http.StatusSeeOther)
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
	IPAddress := r.Header.Get("X-Forwarded-For")
	if IPAddress != "62.76.102.182" {
		http.Error(w, "Incorrect IP", http.StatusBadRequest)
		return
	}
	hash := []byte(fmt.Sprintf("%s%s", respdata.Transid, os.Getenv("wata_sbp_token")))
	signature := makesha256(hash)
	if respdata.Hash != signature {
		http.Error(w, "Incorrect signature", http.StatusBadRequest)
		return
	}
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
	updatedigiseller(w, invoice_id, status)
}

func webhookcryptomus(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Incorrect webhook", http.StatusBadRequest)
		return
	}
	//str := strconv.Quote(string(body))
	var respdata CryptomusWebhookRequestData
	if err := json.Unmarshal(body, &respdata); err != nil {
		http.Error(w, "Incorrect webhook", http.StatusBadRequest)
		return
	}
	var signrespdata CryptomusWebhookRequestSignature
	if err := json.Unmarshal(body, &signrespdata); err != nil {
		http.Error(w, "Incorrect webhook", http.StatusBadRequest)
		return
	}
	data, err := json.Marshal(respdata)
	if err != nil {
		http.Error(w, "Error marshaling JSON:", http.StatusBadRequest)
		return
	}
	data = []byte(strings.Replace(string(data), `/`, `\/`, -1))
	sign := md5hash(data)
	if sign != signrespdata.Signature {
		http.Error(w, "Incorrect signature", http.StatusBadRequest)
		return
	}
	IPAddress := r.Header.Get("X-Forwarded-For")
	if IPAddress != "91.227.144.54" {
		http.Error(w, "Incorrect IP", http.StatusBadRequest)
		return
	}
	status := ""
	if respdata.Status == "paid" || respdata.Status == "paid_over" {
		status = "paid"
	} else if respdata.Status == "refund_process" || respdata.Status == "locked" || respdata.Status == "check" || respdata.Status == "wrong_amount" || respdata.Status == "process" || respdata.Status == "confirm_check" || respdata.Status == "wrong_amount_waiting" {
		status = "wait"
	} else if respdata.Status == "refund_fail" || respdata.Status == "fail" || respdata.Status == "cancel" || respdata.Status == "system_fail" {
		status = "canceled"
	} else if respdata.Status == "refund_paid" {
		status = "refunded"
	} else {
		http.Error(w, "Incorrect status", http.StatusBadRequest)
		return
	}
	invoice_id, err := strconv.ParseInt(respdata.OrderID, 10, 64)
	if err != nil {
		http.Error(w, "Incorrect id", http.StatusBadRequest)
		return
	}
	updatedigiseller(w, invoice_id, status)
}

func updatedigiseller(w http.ResponseWriter, invoice_id int64, status string) {
	client := &http.Client{}
	err := UpdateStatusQuery(connPool, invoice_id, status)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	amount, currency, err := SelectWebhookQuery(connPool, invoice_id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hash := []byte(fmt.Sprintf("amount:%.2f;currency:%s;invoice_id:%d;status:%s;", amount, currency, invoice_id, status))
	signature := sha256hmac(hash)
	apiUrl := "https://digiseller.market/callback/api"
	urlStr := fmt.Sprintf("%s?invoice_id=%d&amount=%.2f&currency=%s&status=%s&signature=%s",
		apiUrl, invoice_id, amount, currency, status, strings.ToUpper(hex.EncodeToString(signature)))
	req, err := http.NewRequest("GET", urlStr, nil)
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

func status(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	var reqdata DigisellerStatus
	reqdata = DigisellerStatus{
		Transid:   query.Get("invoice_id"),
		Sellerid:  query.Get("seller_id"),
		Amount:    query.Get("amount"),
		Currency:  query.Get("currency"),
		Signature: query.Get("signature"),
	}
	invoice_id, err := strconv.ParseInt(reqdata.Transid, 10, 64)
	if err != nil {
		http.Error(w, "Incorrect id", http.StatusBadRequest)
		return
	}
	status := SelectStatusQuery(connPool, invoice_id)
	var answerData DigisellerStatusAnswer
	hash := []byte(fmt.Sprintf("amount:%s;currency:%s;invoice_id:%s;status:%s;", reqdata.Amount, reqdata.Currency, reqdata.Transid, status))
	signature := sha256hmac(hash)
	answerData = DigisellerStatusAnswer{
		Transid:   reqdata.Transid,
		Amount:    reqdata.Amount,
		Currency:  reqdata.Currency,
		Status:    status,
		Signature: strings.ToUpper(hex.EncodeToString(signature)),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(answerData)
}
