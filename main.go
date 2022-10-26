package main

import (
	"encoding/gob"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

type User struct {
	Username      string
	Authenticated bool
}

var cookieName = "session"

var store *sessions.CookieStore

var tpl *template.Template

func init() {
	authKey := securecookie.GenerateRandomKey(64)
	encryptedKey := securecookie.GenerateRandomKey(32)

	store = sessions.NewCookieStore(
		authKey,
		encryptedKey,
	)

	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   60 * 15,
		HttpOnly: true,
	}
	gob.Register(User{})
	tpl = template.Must(template.ParseGlob("templates/*.html"))
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/", Home)
	router.HandleFunc("/login/", Login)
	router.HandleFunc("/secret/", Secret)
	router.HandleFunc("/forbidden/", Forbidden)
	log.Fatal(http.ListenAndServe(":8001", router))
}

func Home(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, cookieName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user := getUser(session)
	tpl.ExecuteTemplate(w, "index.html", user)
}

func Login(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, cookieName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if r.FormValue("password") != "password" {
		if r.FormValue("password") == "" {
			session.AddFlash("Must enter the password")
		}
		session.AddFlash("The password was incorrect")
		err = sessions.Save(r, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/forbidden/", http.StatusFound)
		return
	}

	username := r.FormValue("username")
	user := User{
		Username:      username,
		Authenticated: true,
	}
	// or
	// user := new(User)
	// user.Authenticated = true
	// user.Username = username

	session.Values["user"] = user
	// fmt.Printf("%#v\n", user)

	err = sessions.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/secret/", http.StatusFound)
}

func Secret(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, cookieName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user := getUser(session)

	if auth := user.Authenticated; !auth {
		session.AddFlash("You don't have access!")
		err = sessions.Save(r, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/forbidden/", http.StatusFound)
		return
	}
	tpl.ExecuteTemplate(w, "secret.html", user.Username)
}

func Forbidden(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, cookieName)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	flashMessage := session.Flashes()

	err = session.Save(r, w)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	tpl.ExecuteTemplate(w, "forbidden.html", flashMessage)
}

func getUser(s *sessions.Session) User {
	val := s.Values["user"]
	var user = User{}

	user, ok := val.(User)

	if !ok {
		return User{Authenticated: false}
	}
	return user
}
