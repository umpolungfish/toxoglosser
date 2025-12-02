// Package utils provides utility functions for Toxoglosser toolkit
// including timing obfuscation, sleep patterns, and other helper functions.
package utils

import (
	"crypto/rand"
	"math"
	"time"
)

// getSecureRandomFloat64 returns a secure random float64 between 0.0 and 1.0
func getSecureRandomFloat64() float64 {
	// Generate 8 random bytes
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback to a less secure method if crypto/rand fails
		return math.Float64frombits(time.Now().UnixNano())
	}

	// Convert to uint64 and then to float64 in range [0, 1)
	return float64(int64(uint64(b[0])<<56|uint64(b[1])<<48|uint64(b[2])<<40|uint64(b[3])<<32|
		uint64(b[4])<<24|uint64(b[5])<<16|uint64(b[6])<<8|uint64(b[7]))) /
		float64(math.MaxInt64)
}

// getSecureRandomFloat32 returns a secure random float32 between 0.0 and 1.0
func getSecureRandomFloat32() float32 {
	// Generate 4 random bytes
	b := make([]byte, 4)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback to a less secure method if crypto/rand fails
		return float32(time.Now().UnixNano() & 0xFFFFFFFF)
	}

	// Convert to uint32 and then to float32 in range [0, 1)
	return float32(int32(uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3]))) /
		float32(math.MaxInt32)
}

// SleepWithJitter sleeps for a base duration plus random jitter.
// This helps evade timing-based detection by introducing variability to execution times.
// jitterPercent should be a value between 0.0 and 1.0 representing the percentage of jitter.
func SleepWithJitter(baseDuration time.Duration, jitterPercent float64) {
	// Calculate jitter range
	jitterRange := float64(baseDuration) * jitterPercent
	jitter := time.Duration(getSecureRandomFloat64()*jitterRange - jitterRange/2) // Random value between -jitterRange/2 and +jitterRange/2

	// Calculate final sleep duration
	finalDuration := baseDuration + jitter

	// Ensure the duration is positive
	if finalDuration < 0 {
		finalDuration = baseDuration
	}

	time.Sleep(finalDuration)
}

// SleepWithExponentialBackoff sleeps with exponentially increasing delays and jitter.
// This is useful for anti-sandbox detection as it can make execution appear slower in virtual environments.
// attempt represents the current attempt number (affects delay exponentially).
// maxDuration sets the maximum delay to prevent overly long sleeps.
func SleepWithExponentialBackoff(baseDuration time.Duration, attempt int, maxDuration time.Duration) {
	// Calculate exponential delay
	expDelay := baseDuration * (1 << uint(attempt)) // 2^attempt

	// Add jitter
	jitter := time.Duration(getSecureRandomFloat64() * float64(expDelay) * 0.1) // +/- 10% jitter
	finalDuration := expDelay + jitter

	// Cap at maximum duration
	if finalDuration > maxDuration {
		finalDuration = maxDuration
	}

	time.Sleep(finalDuration)
}

// FoliageStyleSleep implements a more sophisticated sleep pattern that mimics the "Foliage" technique.
// It breaks the sleep into smaller chunks with variable timing to evade sandbox timing checks.
// This technique makes the sleep appear more natural to detection mechanisms.
func FoliageStyleSleep(baseDuration time.Duration) {
	// Break the sleep into smaller chunks with variable timing
	totalSleep := int64(baseDuration)
	chunkSize := int64(100 * time.Millisecond) // 100ms chunks

	// Randomize the chunk size slightly
	chunkVariance := int64(20 * time.Millisecond) // +/- 20ms variance

	for totalSleep > 0 {
		// Calculate current chunk size with variance
		currentChunk := chunkSize
		if getSecureRandomFloat32() > 0.5 {
			currentChunk += int64(getSecureRandomFloat64() * float64(chunkVariance))
		} else {
			currentChunk -= int64(getSecureRandomFloat64() * float64(chunkVariance/2))
		}

		// Ensure we don't sleep longer than remaining time
		if currentChunk > totalSleep {
			currentChunk = totalSleep
		}

		time.Sleep(time.Duration(currentChunk))
		totalSleep -= currentChunk
	}
}