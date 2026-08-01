package main

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
	waLog "go.mau.fi/whatsmeow/util/log"
)

func openDeviceStore(ctx context.Context, log zerolog.Logger, dbPath string) (*sqlstore.Container, error) {
	container, err := sqlstore.New(ctx, "sqlite", fmt.Sprintf("file:%s?_foreign_keys=on&_pragma=busy_timeout=5000", dbPath), waLog.Zerolog(log.With().Str("component", "wa-db").Logger()))
	if err != nil {
		return nil, fmt.Errorf("failed to open device db: %w", err)
	}
	return container, nil
}

func getOrCreateDevice(ctx context.Context, log zerolog.Logger, container *sqlstore.Container) (*store.Device, error) {
	devices, err := container.GetAllDevices(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list devices: %w", err)
	}
	if len(devices) > 0 {
		log.Info().Int("count", len(devices)).Msg("loaded e2ee device")
		return devices[0], nil
	}
	log.Info().Msg("no existing e2ee device, creating new")
	return container.NewDevice(), nil
}
