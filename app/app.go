package app

import (
	"log/slog"
	"time"

	grpcapp "github.com/karkulevskiy/sso/app/grpc"
)

type App struct {
	GRPCServer *grpcapp.App
}

func New(log *slog.Logger,
	grpcPort int,
	storagePath string,
	tokenTTL time.Duration) *App {

	// TODO: инициализировать storage

	// TODO: инициализировать service слой

	grpcApp := grpcapp.New(log, grpcPort)

	return &App{
		GRPCServer: grpcApp,
	}
}
