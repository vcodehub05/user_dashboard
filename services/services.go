package services

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"
	"userdb/entities"
	"userdb/logger"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

const Secretkey = "i love to code"

var mySigningKey = []byte(os.Getenv("SECRET_KEY"))

type response struct {
	ID      int64  `json:"id,omitempty"`
	Message string `json:"message,omitempty"`
}

func CreateConnection() *sql.DB {

	var host = os.Getenv("postgres_HOST")
	var port = os.Getenv("postgres_PORT")
	var user = os.Getenv("postgres_USER1")
	var password = os.Getenv("postgres_PASSWORD")
	var dbname = os.Getenv("postgres_DBNAME")

	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)
	db, err := sql.Open("postgres", psqlInfo)

	if err != nil {
		fmt.Println(err)
	}
	err = db.Ping()
	if err != nil {
		fmt.Println(err)
	}
	logger.InfoLogger.Println("db Successfully connected!")
	fmt.Println("Successfully connected!")
	return db
}
func CreateUser(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Context-Type", "application/x-www-form-urlencoded")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	var user entities.User
	err := json.NewDecoder(r.Body).Decode(&user)

	if err != nil {
		fmt.Printf("Unable to decode the request body.  %v", err)
	}
	msg, issue := Validate(&user)
	if issue {
		insertID := insertUser(user)
		var report string
		if insertID == 0 {
			report = "user already exist1"
			json.NewEncoder(w).Encode(report)
		} else {
			res := response{
				ID:      insertID,
				Message: "user created Successfully",
			}
			logger.InfoLogger.Println(res)
			json.NewEncoder(w).Encode(res)
		}
	} else {
		res := msg
		logger.InfoLogger.Println(res)
		json.NewEncoder(w).Encode(res)
	}
}
func GetUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Context-Type", "application/x-www-form-urlencoded")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	params := mux.Vars(r)
	id, err := strconv.Atoi(params["id"])

	if err != nil {
		fmt.Printf("Unable to convert the string into int.  %v", err)
		logger.ErrorLogger.Printf("Unable to convert the string into int.  %v", err)
	}
	user, err := getUser(int64(id))
	if err != nil {
		logger.ErrorLogger.Printf("User id is wrong or it is deleted %v", err)
		fmt.Printf("User id is wrong or it is deleted %v", err)
	}
	json.NewEncoder(w).Encode(user)
}
func GetAllUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Context-Type", "application/x-www-form-urlencoded")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	sortTypes := r.URL.Query().Get("sortTypes")
	sortBy := r.URL.Query().Get("sortBy")
	page := r.URL.Query().Get("page")
	users, err := getAllUser(sortBy, sortTypes, page)

	if err != nil {
		fmt.Printf("Unable to get all user %v", err)
		logger.ErrorLogger.Printf("Unable to get all user %v", err)
	}

	json.NewEncoder(w).Encode(users)
}
func UpdateUser(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "PUT")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	params := mux.Vars(r)
	id, err := strconv.Atoi(params["id"])
	if err != nil {
		logger.ErrorLogger.Printf("Unable to convert the string into int.  %v", err)
		fmt.Printf("Unable to convert the string into int.  %v", err)
	}
	var user entities.User

	err = json.NewDecoder(r.Body).Decode(&user)

	if err != nil {
		fmt.Printf("Unable to decode the request body.  %v", err)
		logger.ErrorLogger.Printf("Unable to decode the request body.  %v", err)
	}
	_ = updateUser(int64(id), user)
	msg := "user updated successfully. Total rows/record affected "

	res := response{
		ID:      int64(id),
		Message: msg,
	}
	logger.InfoLogger.Println(res)
	json.NewEncoder(w).Encode(res)
}
func DeleteUser(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Context-Type", "application/x-www-form-urlencoded")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// get the id from the request params, key is "id"
	params := mux.Vars(r)

	// convert the id in string to int
	id, err := strconv.Atoi(params["id"])

	if err != nil {
		fmt.Printf("Unable to convert the string into int.  %v", err)
		logger.ErrorLogger.Printf("Unable to convert the string into int.  %v", err)
	}
	deleteUser(int64(id))
	msg := "User deleted  successfully. "
	res := response{
		ID:      int64(id),
		Message: msg,
	}
	logger.InfoLogger.Println(res)
	json.NewEncoder(w).Encode(res)
}
func SearchUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("seraching")
	w.Header().Set("Context-Type", "application/x-www-form-urlencoded")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	searchUser := r.URL.Query().Get("search")

	users, err := search(searchUser)

	if err != nil {
		fmt.Printf("no user found of this name %v", err)
		logger.ErrorLogger.Printf("no user found of this name %v", err)
	}

	json.NewEncoder(w).Encode(users)
}
func Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Context-Type", "application/x-www-form-urlencoded")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "Post")

	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	var login entities.Login_info
	var count int
	var msg string
	var pas []byte
	err := json.NewDecoder(r.Body).Decode(&login)
	if err != nil {
		fmt.Printf("no input from user  %v", err)
		logger.ErrorLogger.Printf("no input from user  %v", err)
	}
	db := CreateConnection()
	defer db.Close()
	sqlStatement := `SELECT count(email) FROM employe_log WHERE archived=false and email=$1 `
	row := db.QueryRow(sqlStatement, login.Email)
	err = row.Scan(&count)
	if err != nil {
		fmt.Println(err)
		logger.ErrorLogger.Println(err)
	}
	sqlStatement = `SELECT password FROM employe_log WHERE email=$1 `
	row = db.QueryRow(sqlStatement, login.Email)
	err = row.Scan(&pas)
	if err != nil {
		fmt.Println(err)
		logger.ErrorLogger.Println(err)
	}

	if count == 0 {
		msg = "user not found with the given email"
		fmt.Println(msg)
		logger.InfoLogger.Println(msg)
		json.NewEncoder(w).Encode(msg)
	}
	if err := bcrypt.CompareHashAndPassword(pas, []byte(login.Password)); err != nil {
		msg = "password is incorrect"
		fmt.Println(msg)
		logger.InfoLogger.Println(msg)
		json.NewEncoder(w).Encode(msg)

	} else {
		msg = "access granted"
		fmt.Println(msg)
		logger.InfoLogger.Println(msg)
		validToken, err := GetJWT()
		if err != nil {
			fmt.Println("Failed to generate token")
			logger.ErrorLogger.Printf("failed to generate token %v", err)
		}
		cookie := &http.Cookie{
			Name:     "token-test",
			Value:    validToken,
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)

	}
}
func insertUser(user entities.User) int64 {

	db := CreateConnection()
	defer db.Close()
	var password []byte
	password, _ = bcrypt.GenerateFromPassword([]byte(user.Password), 6)
	sqlStatement := `INSERT INTO employe_log (first_name,last_name,email,dob,password,created_at,archived) VALUES ($1, $2,$3,$4,$5,$6,$7) RETURNING user_id`
	var id int64
	err := db.QueryRow(sqlStatement, user.FirstName, user.LastName, user.Email, user.DOB, password, time.Now(), false).Scan(&id)

	if err != nil {
		fmt.Printf("Unable to execute the query. %v", err)
		logger.ErrorLogger.Printf("Unable to execute the query. %v", err)
	} else {
		fmt.Printf("User created , your user id is %v", id)
		logger.InfoLogger.Printf("User created , your user id is %v", id)
		return id
	}
	return id
}
func getUser(id int64) (entities.User, error) {
	db := CreateConnection()
	defer db.Close()
	var user entities.User
	sqlStatement := `SELECT first_name,last_name,email,dob FROM employe_log WHERE user_id=$1 AND archived=$2`
	row := db.QueryRow(sqlStatement, id, false)

	// unmarshal the row object to user
	err := row.Scan(&user.FirstName, &user.LastName, &user.Email, &user.DOB)
	if err == nil {
		sqlStatement1 := `UPDATE employe_log SET last_access_at=$2 WHERE user_id=$1`
		_, _ = db.Exec(sqlStatement1, id, time.Now())
	}

	switch err {
	case sql.ErrNoRows:
		fmt.Println("user id dosent exist")
		logger.ErrorLogger.Println("user id dosent exist")
		return user, nil
	case nil:
		return user, nil
	default:
		fmt.Printf("Unable to scan the row. %v", err)
		logger.ErrorLogger.Printf("Unable to scan the row. %v", err)
	}
	return user, err
}
func getAllUser(shorBy string, shortType string,  page string) ([]entities.User, error) {

	db := CreateConnection()
	defer db.Close()

	var users []entities.User

	sqlStatement := "SELECT user_id,first_name,last_name,email,dob  FROM employe_log WHERE archived=false "

	if len(shorBy) != 0 && len(shortType) != 0 {
		sqlStatement = fmt.Sprintf("SELECT user_id,first_name,last_name,email,dob  FROM employe_log WHERE archived=false ORDER BY %v %v", shorBy, shortType)
	} else {
		shorBy = "first_name"
		shortType = "asc"
	}
	
	items := 2
	if page == "" {
		page = "1"
	}
	p, _ := strconv.Atoi(page)
	off := (p - 1) * items
	sqlStatement += fmt.Sprintf(" LIMIT %d OFFSET %d", items, off)
	rows, err := db.Query(sqlStatement)
	if err != nil {
		fmt.Printf("Unable to execute the query. %v", err)
		logger.ErrorLogger.Printf("Unable to execute the query. %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var user entities.User
		err = rows.Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.DOB)

		if err != nil {
			fmt.Printf("Unable to scan the row. %v", err)
			logger.ErrorLogger.Printf("Unable to scan the row. %v", err)
		}
		users = append(users, user)

	}
	return users, err
}
func updateUser(id int64, user entities.User) int64 {

	db := CreateConnection()
	defer db.Close()
	sqlStatement := `UPDATE employe_log SET first_name=$2, last_name=$3 ,email=$4,dob=$5 WHERE user_id=$1`
	res, err := db.Exec(sqlStatement, id, &user.FirstName, &user.LastName, &user.Email, &user.DOB)

	if err != nil {
		fmt.Printf("Unable to execute the query. %v", err)
		logger.ErrorLogger.Printf("Unable to execute the query. %v", err)
	}
	if err == nil {
		sqlStatement1 := `UPDATE employe_log SET updated_at=$2 WHERE user_id=$1`
		_, _ = db.Exec(sqlStatement1, id, time.Now())
	}
	rowsAffected, err := res.RowsAffected()

	if err != nil {
		fmt.Printf("Error while checking the affected rows. %v", err)
		logger.ErrorLogger.Printf("Error while checking the affected rows. %v", err)
	}

	fmt.Printf("Total rows/record affected %v", rowsAffected)
	logger.InfoLogger.Printf("Total rows/record affected %v", rowsAffected)
	return rowsAffected
}
func deleteUser(id int64) {

	db := CreateConnection()

	defer db.Close()
	sqlStatement := `UPDATE employe_log SET archived=$2 WHERE user_id=$1`
	_, err := db.Exec(sqlStatement, id, true)

	if err != nil {
		fmt.Printf("Unable to execute the query. %v", err)
		logger.ErrorLogger.Printf("Unable to execute the query. %v", err)
	}

	if err != nil {
		fmt.Printf("Error while checking the affected rows. %v", err)
		logger.ErrorLogger.Printf("Error while checking the affected rows. %v", err)
	}
	fmt.Println("Total rows/record affected ")
	logger.InfoLogger.Println("Total rows/record affected ")
	return
}

func search(sear string) ([]entities.User, error) {
	db := CreateConnection()
	defer db.Close()

	sear = fmt.Sprintf("%%%s%%", sear)
	sqlStatement := `SELECT user_id,first_name,last_name,email,dob  FROM employe_log WHERE first_name LIKE $1`
	rows, err := db.Query(sqlStatement, sear)

	var users []entities.User
	if err != nil {
		fmt.Printf("Unable to execute the query. %v", err)
		logger.ErrorLogger.Printf("Unable to execute the query. %v", err)
		return nil, err
	}

	defer rows.Close()
	for rows.Next() {
		var user entities.User
		err = rows.Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.DOB)
		fmt.Print(err)
		if err != nil {
			fmt.Printf("Unable to scan the row. %v", err)
			logger.ErrorLogger.Printf("Unable to scan the row. %v", err)
		}
		users = append(users, user)

	}
	return users, err

}
func GetJWT() (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true

	claims["exp"] = time.Now().Add(time.Minute * 1).Unix()

	tokenString, err := token.SignedString(mySigningKey)

	if err != nil {
		fmt.Errorf("Something Went Wrong: %s", err.Error())
		return "", err
	}

	return tokenString, nil
}
func Validate(vali *entities.User) (string, bool) {

	msg := "sucessfully registred"
	if (len(vali.FirstName) + len(vali.LastName)) > 30 {
		msg = "name is to large "
		return msg, false //just an error
	}
	//check for valid email or not

	if len(vali.Email) > 20 {
		msg = "email is too long"
		return msg, false
	}
	// if valid(vali.Email) {

	// } else {
	// 	msg = "email is not valid"
	// 	return msg, false
	// }
	if already_exist(vali.Email) {
		msg = "email already exist"
		return msg, false

	} 
	if (len(vali.Password) < 8) || (len(vali.Password) > 20) {
		msg = "passwor should be minimum 8 characters and maximum 20 characters"
		return msg, false
	} //no.s special character , password strength, 1 letter should be numeric/specila/uppercase/lowercase
	return msg,true
}
//checks if email already exist
func already_exist(email1 string) bool {
	db := CreateConnection()
	var count int64
	count = 0
	
	err := db.QueryRow("SELECT count(*) FROM employe_log WHERE email=$1 and archived=false", email1).Scan(&count)
	if err != nil {
		fmt.Println(err)
	}
	if count == 0 {
		return false
	} else {
		return true
	}
}
