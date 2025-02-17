package main

import (
	"fmt"
	"net/http"
	"securelogin/utils"
	"time"
)

type Login struct {
    HashedPassword string
    SessionToken string
    CSRFToken string
}

//key is username
var users = map[string]Login{}

func main() {
    http.HandleFunc("/register", register)
    http.HandleFunc("/login", login)
    http.HandleFunc("/logout", logout)
    http.HandleFunc("/protected", protected)
    http.ListenAndServe(":8080", nil)
}

func register(w http.ResponseWriter, r *http.Request){
    if r.Method != http.MethodPost {
        er := http.StatusMethodNotAllowed
        http.Error(w, "Invalid method", er)
        return
    }

    username := r.FormValue("username")
    password := r.FormValue("password")

    if len(username) < 8 || len(password) < 8 {
        er := http.StatusNotAcceptable
        http.Error(w, "Invalid username/password", er)
        return
    }

    if _, ok := users[username]; ok {
        er := http.StatusConflict
        http.Error(w, "User already exists", er)
        return
    }
	hashedPassword, _ := utils.HashPassword(password)
	users[username] = Login{
		HashedPassword: hashedPassword,
	}

	fmt.Fprintln(w, "User registered successfully!")

}

func login(w http.ResponseWriter, r *http.Request){
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid Request method", er)
		return
	}

	username := r.FormValue("username")
    password := r.FormValue("password")

	user, ok := users[username]
	if !ok || !utils.CheckPasswordHash(password, user.HashedPassword) {
		er := http.StatusUnauthorized
		http.Error(w, "Invalid username or password", er)
		return
	}

	sessionToken := utils.GenerateToken(32)
	csrfToken := utils.GenerateToken(32)

	//Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name: "session_token",
		Value: sessionToken,
		Expires: time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})

	//Set CSRF token in a cookie
	http.SetCookie(w, &http.Cookie{
		Name: "csrf_token",
		Value: csrfToken,
		Expires: time.Now().Add(24 * time.Hour),
		HttpOnly: false,
	})

	//Store Token in db
	user.SessionToken = sessionToken
	user.CSRFToken = csrfToken
	users[username] = user

	fmt.Fprintln(w, "Login successfully!")
}

func protected(w http.ResponseWriter, r *http.Request){
	if r.Method != http.MethodPost {
		er := http.StatusMethodNotAllowed
		http.Error(w, "Invalid request method", er)
		return
	}

	if err := Authorize(r); err != nil {
		er := http.StatusUnauthorized
		http.Error(w, "Unauthorized", er)
		return
	}

	username := r.FormValue("username")
	fmt.Fprintf(w, "CSRF validation successful! Welcome, %s", username)
}


func logout(w http.ResponseWriter, r *http.Request){
	if err := Authorize(r); err != nil {
		er := http.StatusUnauthorized
		http.Error(w, "Unauthorized", er)
		return
	}

	//Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name: "session_token",
		Value: "",
		Expires: time.Now().Add(-time.Hour),
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name: "csrf_token",
		Value: "",
		Expires: time.Now().Add(-time.Hour),
		HttpOnly: false,
	})

	//Clear from the db
	username := r.FormValue("username")
	user, _ := users[username]
	user.SessionToken = ""
	user.CSRFToken = ""
	users[username] = user

	fmt.Fprintln(w, "Logged out successfully!")
}

// func Authorize(r *http.Request) error {
// 	cookie, err := r.Cookie("session_token")
// 	if err != nil {
// 		return fmt.Errorf("Unauthorized: No session token")
// 	}

// 	// ตรวจสอบว่า session token นั้นถูกต้องหรือไม่
// 	username := r.FormValue("username")
// 	user, ok := users[username]
// 	if !ok || user.SessionToken != cookie.Value {
// 		return fmt.Errorf("Unauthorized: Invalid session token")
// 	}

// 	return nil
// }


