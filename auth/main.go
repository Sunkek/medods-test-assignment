package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"

	"net/http"

	"github.com/Sunkek/medods-test-assignment/auth/db"
	"github.com/Sunkek/medods-test-assignment/auth/handlers"
	"github.com/gorilla/mux"
)

func main() {
	log.SetOutput(os.Stdout)
	// Connecting to the database
	client := db.InitDB()
	Handler := handlers.MHandler{DB: client.Database("medods")}
	defer client.Disconnect(context.Background())

	// Fetch the user docs
	usersCollection := client.Database("medods").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cursor, err := usersCollection.Find(ctx, bson.M{})
	if err != nil {
		log.Fatal(err)
	}
	var users []bson.M
	if err = cursor.All(ctx, &users); err != nil {
		log.Fatal(err)
	}
	fmt.Println(users)

	// Instantiating the gorilla/mux router
	r := mux.NewRouter()
	r.HandleFunc("/ping", Ping).Methods("GET")
	r.HandleFunc("/authorize/{user_id}", Handler.Authorize).Methods("GET")
	r.HandleFunc("/refresh", Handler.Refresh).Methods("POST")

	// Our application will run on port 8080. Here we declare the port and pass in our router.
	http.ListenAndServe(":8080", r)
}

// Ping handler. Whenever an API endpoint is hit
// we will simply return the message "Pong"
var Ping = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Pong"))
})
