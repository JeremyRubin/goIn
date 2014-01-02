// Copyright 2014 Jeremy Rubin

// This file is part of goIn.

// goIn is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// goIn is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with goIn.  If not, see <http://www.gnu.org/licenses/>.

package goIn

import "code.google.com/p/go.crypto/bcrypt"
import "net/http"
import "github.com/gorilla/sessions"

// string ->:stored bcrypt hash, bool -> user exists
type GetUser func(user string) (string, bool)

// generate a user, return error if username/password are bad.
type MakeUser func(user, hash string) *error

//Don't store password, but validate it meets security requirements
type ValidPassword func(password string) bool

type PasswordMiddleware struct {
	getUser       GetUser
	makeUser      MakeUser
	validPassword ValidPassword
	servicename   string
	keypairs      [][]byte
	cost          int
	// If not set, must call Init method
	cookies *sessions.CookieStore
}

func (pm *PasswordMiddleware) Init() {
	pm.cookies = sessions.NewCookieStore(pm.keypairs...)
}
func (pm *PasswordMiddleware) get(r *http.Request) (*sessions.Session, error) {
	return pm.cookies.Get(r, pm.servicename)
}

func (pm *PasswordMiddleware) addSession(username string, w http.ResponseWriter, r *http.Request) {
	if session, err := pm.cookies.New(r, pm.servicename); err == nil {
		session.Values["username"] = username
		session.Save(r, w)
	} else {
		//TODO: User logged in??
	}
}

func (pm *PasswordMiddleware) Auth(accept http.HandlerFunc, reject http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if session, _ := pm.get(r); session.IsNew {
			reject(w, r)
		} else {
			accept(w, r)
		}
	}
}

func (pm *PasswordMiddleware) Login(accept http.HandlerFunc, reject http.HandlerFunc) http.HandlerFunc {
	// Check if cookie exists
	// then fall back to trying to log in
	// then fail
	newReject := func(w http.ResponseWriter, r *http.Request) {
		username := r.PostFormValue("username")
		password := r.PostFormValue("password")
		if hash, exists := pm.getUser(username); exists && bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil {
			pm.addSession(username, w, r)
			accept(w, r)
		} else {
			reject(w, r)
		}
	}
	return pm.Auth(accept, newReject)
}
func (pm *PasswordMiddleware) Logout(accept http.HandlerFunc, reject http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if session, _ := pm.get(r); !session.IsNew {
			session.Options.MaxAge = -1
			session.Save(r, w)
			accept(w, r)
		} else {
			reject(w, r)
		}
	}
}

func (pm *PasswordMiddleware) NewUser(accept http.HandlerFunc, reject http.HandlerFunc) http.HandlerFunc {
	// If username does not exist, then create the user then log them in
	// If user name does exist, reject
	accept = pm.Login(accept, reject)
	return func(w http.ResponseWriter, r *http.Request) {

		username := r.PostFormValue("username")
		password := r.PostFormValue("password")
		if !pm.validPassword(password) {
			reject(w, r)
		} else if hash, err := bcrypt.GenerateFromPassword([]byte(password), pm.cost); err != nil {
			reject(w, r)
		} else if err := pm.makeUser(username, string(hash)); err == nil {
			accept(w, r)
		} else {
			reject(w, r)
		}
	}
}

// TODO: fuckit, I'll do it later
func (pm *PasswordMiddleware) ChangePassword(accept http.HandlerFunc, reject http.HandlerFunc) http.HandlerFunc {
	// If username does not exist, then create the user then log them in
	// If user name does exist, reject
	accept = pm.Login(accept, reject)
	return func(w http.ResponseWriter, r *http.Request) {

		password := r.PostFormValue("password")
		username := r.PostFormValue("username")
		if !pm.validPassword(password) {
			reject(w, r)
		} else if hash, err := bcrypt.GenerateFromPassword([]byte(password), pm.cost); err != nil {
			reject(w, r)
		} else if err := pm.makeUser(username, string(hash)); err == nil {
			accept(w, r)
		} else {
			reject(w, r)
		}
	}
}
