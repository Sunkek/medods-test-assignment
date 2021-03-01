package db

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

type tokenData struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	UserID    uuid.UUID          `bson:"user_id"`
	TokenID   []byte             `bson:"token_id"`
	CreatedAt time.Time          `bson:"created_at"`
}

// InitDB creates and returns a pointer to a mongodb client
func InitDB() *mongo.Client {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second) // TODO Add some retry logic
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://mongodb:27017"))
	if err != nil {
		log.Fatal(err)
	} else {
		log.Println("Connected to Database")
	}
	populateDB(client) // May comment this out if you have some users present already
	return client
}

func populateDB(c *mongo.Client) {
	// Drop existing collections - just in case
	usersCollection := c.Database("medods").Collection("users")
	tokensCollection := c.Database("medods").Collection("refresh_tokens")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := usersCollection.Drop(ctx); err != nil {
		log.Println(err)
	}
	if err := tokensCollection.Drop(ctx); err != nil {
		log.Println(err)
	}
	// Create unique index for user ID
	_, err := usersCollection.Indexes().CreateOne(
		context.Background(),
		mongo.IndexModel{
			Keys:    bson.D{{Key: "user_id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
	)
	if err != nil {
		log.Println(err)
	}
	// Create unique index for token ID
	_, err = tokensCollection.Indexes().CreateOne(
		context.Background(),
		mongo.IndexModel{
			Keys:    bson.D{{Key: "token_id", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
	)
	if err != nil {
		log.Println(err)
	}
	// Create an autodelete index for token entries
	_, err = tokensCollection.Indexes().CreateOne(
		context.Background(),
		mongo.IndexModel{
			Keys:    bson.D{{Key: "created_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(60 * 60 * 12), // TODO Put this in .env so it's synced with token's expiration
		},
	)
	if err != nil {
		log.Println(err)
	}

	// Add some users
	GUIDs := []string{
		"8e190df3-599b-4f0c-9067-dbae2e6227bd",
		"40fa5155-0a0a-4da8-b8d1-78b6e92d1237",
		"691acc89-6e12-4217-9ac3-fbd3381794cc",
		"e79cd612-3812-4c36-97cd-caf01c19f49d",
		"8be92bf9-d76d-4f51-8bb0-6b2a572b1e48",
	}
	for _, id := range GUIDs {
		guid, err := uuid.Parse(id)
		if err != nil {
			log.Println(err)
		}
		_, err = usersCollection.InsertOne(ctx, bson.M{"user_id": guid})
		if err != nil {
			log.Println(err)
		}
	}
}

// SaveToken saves a refresh token ID to database
func SaveToken(coll *mongo.Collection, userID uuid.UUID, tokenID string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(tokenID), bcrypt.MinCost)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = coll.InsertOne(ctx, bson.M{
		"user_id":    userID,
		"token_id":   hash,
		"created_at": time.Now(),
	})
	return err
}

// DeleteToken deletes a refresh token ID from the database
func DeleteToken(coll *mongo.Collection, userID uuid.UUID, tokenID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cursor, err := coll.Find(ctx, bson.M{"user_id": userID})
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var tokenDoc tokenData
		if err = cursor.Decode(&tokenDoc); err != nil {
			return err
		}
		err = bcrypt.CompareHashAndPassword(tokenDoc.TokenID, []byte(tokenID))
		if err == nil {
			_, err = coll.DeleteOne(ctx, tokenDoc)
			return nil
		}
	}
	return fmt.Errorf("This token ID is expired or was used already")
}
