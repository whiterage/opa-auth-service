package main

import (
	"context"
	"log"

	"github.com/whiterage/opa-auth-service/internal/app"
)

func main() {
	if err := app.Run(context.Background()); err != nil {
		log.Fatal(err)
	}
}
