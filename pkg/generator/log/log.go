package log

import (
	"fmt"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var Logger *zap.SugaredLogger

func SetLogger() error {
	loggerConfig := zap.NewProductionConfig()
	if viper.GetBool("debug") {
		loggerConfig.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}
	logger, err := loggerConfig.Build()
	if err != nil {
		return fmt.Errorf("failed to initialize zap logger: %w", err)
	}
	defer logger.Sync()
	Logger = logger.Sugar()
	return nil
}
