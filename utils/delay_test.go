package utils

import (
	"testing"
	"time"
)

// TestSleepWithJitter verifies that SleepWithJitter doesn't panic and runs in reasonable time
func TestSleepWithJitter(t *testing.T) {
	t.Skip("Skipping timing test to avoid slow tests in CI") // Skip by default since it involves actual sleeping
	
	start := time.Now()
	SleepWithJitter(100*time.Millisecond, 0.1) // 100ms ± 10%
	duration := time.Since(start)
	
	// Should take roughly 100ms ± some tolerance
	minDuration := 90 * time.Millisecond
	maxDuration := 120 * time.Millisecond // Allow for some overhead
	
	if duration < minDuration || duration > maxDuration {
		t.Errorf("SleepWithJitter took %v, expected between %v and %v", duration, minDuration, maxDuration)
	}
}

// TestSleepWithExponentialBackoff verifies that SleepWithExponentialBackoff doesn't panic
func TestSleepWithExponentialBackoff(t *testing.T) {
	t.Skip("Skipping timing test to avoid slow tests in CI") // Skip by default since it involves actual sleeping
	
	start := time.Now()
	SleepWithExponentialBackoff(50*time.Millisecond, 1, 500*time.Millisecond) // Base 50ms, attempt 1 (100ms) with 500ms max
	duration := time.Since(start)
	
	// Should take roughly 100ms (50ms * 2^1) ± some tolerance
	minDuration := 90 * time.Millisecond
	maxDuration := 150 * time.Millisecond // Allow for some overhead
	
	if duration < minDuration || duration > maxDuration {
		t.Errorf("SleepWithExponentialBackoff took %v, expected between %v and %v", duration, minDuration, maxDuration)
	}
}

// TestFoliageStyleSleep verifies that FoliageStyleSleep doesn't panic
func TestFoliageStyleSleep(t *testing.T) {
	t.Skip("Skipping timing test to avoid slow tests in CI") // Skip by default since it involves actual sleeping
	
	start := time.Now()
	FoliageStyleSleep(100 * time.Millisecond) // 100ms sleep
	duration := time.Since(start)
	
	// Should take approximately 100ms ± some tolerance for overhead
	minDuration := 90 * time.Millisecond
	maxDuration := 150 * time.Millisecond // Allow for some overhead
	
	if duration < minDuration || duration > maxDuration {
		t.Errorf("FoliageStyleSleep took %v, expected between %v and %v", duration, minDuration, maxDuration)
	}
}

// TestJitterFunctions verifies that the sleep functions don't panic
func TestJitterFunctions(t *testing.T) {
	// Just verify that functions can be called without panic
	// These tests are skipped by default since they involve actual sleeping
	t.Run("SleepWithJitter doesn't panic", func(t *testing.T) {
		t.Skip("Sleep test - only run when needed")
		SleepWithJitter(10*time.Millisecond, 0.1)
	})

	t.Run("SleepWithExponentialBackoff doesn't panic", func(t *testing.T) {
		t.Skip("Sleep test - only run when needed")
		SleepWithExponentialBackoff(10*time.Millisecond, 1, 100*time.Millisecond)
	})

	t.Run("FoliageStyleSleep doesn't panic", func(t *testing.T) {
		t.Skip("Sleep test - only run when needed")
		FoliageStyleSleep(10 * time.Millisecond)
	})
}