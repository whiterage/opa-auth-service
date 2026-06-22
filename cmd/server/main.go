package main

import (
	"context"
	"log"

	"testsbertech/internal/app"
)

func main() {
	if err := app.Run(context.Background()); err != nil {
		log.Fatal(err)
	}
}
