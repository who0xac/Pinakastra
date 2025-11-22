package executor

import (
	"context"
	"fmt"
	"math"
	"time"
)

type RetryConfig struct {
	MaxAttempts int
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
}

func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:  3,
		InitialDelay: time.Second,
		MaxDelay:     30 * time.Second,
		Multiplier:   2.0,
	}
}

type RetryableFunc func() (interface{}, error)

func Retry(ctx context.Context, cfg RetryConfig, fn RetryableFunc) (interface{}, error) {
	var lastErr error
	delay := cfg.InitialDelay

	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		result, err := fn()
		if err == nil {
			return result, nil
		}

		lastErr = err

		if attempt < cfg.MaxAttempts {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}

			// Exponential backoff
			delay = time.Duration(float64(delay) * cfg.Multiplier)
			if delay > cfg.MaxDelay {
				delay = cfg.MaxDelay
			}
		}
	}

	return nil, fmt.Errorf("max retries (%d) exceeded: %w", cfg.MaxAttempts, lastErr)
}

func RetryWithJitter(ctx context.Context, cfg RetryConfig, fn RetryableFunc) (interface{}, error) {
	var lastErr error
	delay := cfg.InitialDelay

	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		result, err := fn()
		if err == nil {
			return result, nil
		}

		lastErr = err

		if attempt < cfg.MaxAttempts {
			// Add jitter: random value between 0.5 and 1.5 of delay
			jitteredDelay := time.Duration(float64(delay) * (0.5 + math.Mod(float64(time.Now().UnixNano()), 1.0)))

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(jitteredDelay):
			}

			delay = time.Duration(float64(delay) * cfg.Multiplier)
			if delay > cfg.MaxDelay {
				delay = cfg.MaxDelay
			}
		}
	}

	return nil, fmt.Errorf("max retries (%d) exceeded: %w", cfg.MaxAttempts, lastErr)
}
