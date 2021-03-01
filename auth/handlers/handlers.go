package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/Sunkek/medods-test-assignment/auth/db"
	"github.com/Sunkek/medods-test-assignment/auth/jwtokens"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// MHandler struct allows us to use the same database connection
// for all requests instead of opening and closing it each time
type MHandler struct {
	DB *mongo.Database
}

// Authorize returns a pair of Access and Refresh JWTs
// for the provided user GUID, if it exists in the database
func (h *MHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	usersCollection := h.DB.Collection("users")
	// Check if the user exists
	guid, err := uuid.Parse(vars["user_id"])
	if err != nil {
		log.Println(err)
		RespondWithError(w, http.StatusBadRequest, "Can't parse provided GUID")
		return
	}
	var user bson.M
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = usersCollection.FindOne(ctx, bson.M{"user_id": guid}).Decode(&user); err != nil {
		log.Println(err)
		RespondWithError(w, http.StatusNotFound, "Can't find user with provided GUID")
		return
	}
	// Issue tokens
	tokens, tokenID, err := jwtokens.GiveTokens(guid)
	if err != nil {
		log.Println(err)
		RespondWithError(w, http.StatusInternalServerError, "Can't issue tokens")
		return
	}
	tokensCollection := h.DB.Collection("refresh_tokens")
	err = db.SaveToken(tokensCollection, guid, tokenID)
	if err != nil {
		log.Println(err)
		RespondWithError(w, http.StatusInternalServerError, "Can't store token data")
		return
	}

	RespondWithJSON(w, http.StatusOK, tokens)
	return
}

// Refresh returns a pair of new Access and Refresh JWTs
// for the provided pair of Access and Refresh JWTs
// if they were issued together and for the same user
func (h *MHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	// Decode JSON
	var tokens jwtokens.TokenPair
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&tokens); err != nil {
		RespondWithError(w, http.StatusBadRequest, "Invalid resquest payload")
		return
	}
	// Check tokens and parse user and token IDs
	userID, oldTokenID, err := jwtokens.CheckTokens(tokens)
	if err != nil {
		RespondWithError(w, http.StatusBadRequest, err.Error())
		return
	}
	user, err := uuid.Parse(userID)
	if err != nil {
		RespondWithError(w, http.StatusBadRequest, "Can't parse provided GUID")
		return
	}

	// Issue tokens
	tokensCollection := h.DB.Collection("refresh_tokens")
	err = db.DeleteToken(tokensCollection, user, oldTokenID)
	if err != nil {
		log.Println(err)
		RespondWithError(w, http.StatusInternalServerError, "Can't issue tokens")
		return
	}
	tokens, newTokenID, err := jwtokens.GiveTokens(user)
	if err != nil {
		log.Println(err)
		RespondWithError(w, http.StatusInternalServerError, "Can't issue tokens")
		return
	}
	err = db.SaveToken(tokensCollection, user, newTokenID)
	if err != nil {
		log.Println(err)
		RespondWithError(w, http.StatusInternalServerError, "Can't store token data")
		return
	}

	RespondWithJSON(w, http.StatusOK, tokens)
	return
}
