package driveutil

import (
	"context"
	"log"
	"os"

	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
)

// GetDriveService initializes a Google Drive API client using credentials.json
func GetDriveService() (*drive.Service, error) {
	ctx := context.Background()

	b, err := os.ReadFile("credentials.json")
	if err != nil {
		log.Printf("Unable to read credentials file: %v", err)
		return nil, err
	}

	srv, err := drive.NewService(ctx, option.WithCredentialsJSON(b), option.WithScopes(drive.DriveScope))
	if err != nil {
		log.Printf("Unable to create Drive client: %v", err)
		return nil, err
	}

	return srv, nil
}
