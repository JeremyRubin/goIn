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



type GetUser func(user string) (string, bool)

type PasswordMiddleware struct{
    getUser GetUser
    servicename string
}



func (pm *PasswordMiddleware) Auth(accept http.HandlerFunc, reject http.HandlerFunc) http.HandlerFunc{
    return func(w http.ResponseWriter, r *http.request){
        if //TODO Read cookie here 
            accept(w,r)
        }
        else{
            reject(w,r)
        }
    }
}

func (pm *PasswordMiddleware) Login(accept http.HandlerFunc, reject http.HandlerFunc) http.HandlerFunc{
    // Check if cookie exists
    // then fall back to trying to log in
    // then fail
    reject := func(w http.ResponseWriter, r *http.request){
        username := r.PostFormValue("username")
        password := r.PostFormValue("password")
        else if hash, exists := pm.getUser(username); CompareHashAndPassword(hash,password)==nil{
           //TODO set cookie here 
            accept(w,r)
        }
        else{
            reject(w,r)
        }
    }
    return pm.Auth(accept,reject)
}
func (pm *PasswordMiddleware) Logout(accept http.HandlerFunc, reject http.HandlerFunc) http.HandlerFunc{
    return func(w http.ResponseWriter, r *http.request){
        if //TODO Delete Cookie Here 
            accept(w,r)
        }
        else{
            reject(w,r)
        }
    }
}

func (pm *PasswordMiddleware) NewUser(accept http.HandlerFunc, reject http.HandlerFunc) http.HandlerFunc{
    // If username does not exist, then create the user then log them in

    // If user name does not exist, reject
    accept := pm.Auth(accept, reject)
    return func(w http.ResponseWriter, r *http.request){
        username := r.PostFormValue("username")
        if hash, bool := pm.getUser(username); !bool{ 
            // TODO: Create a new user
            accept(w,r)
        }
        else{
            // Don't create a new user
            return reject(w,r)
        }
    }
}
