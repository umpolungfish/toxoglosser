package utils

import (
	"math/rand"
	"time"
)

// SleepWithJitter sleeps for a base duration plus random jitter
// This helps evade timing-based detection
func SleepWithJitter(baseDuration time.Duration, jitterPercent float64) {
	// Calculate jitter range
	jitterRange := float64(baseDuration) * jitterPercent
	jitter := time.Duration(rand.Float64()*jitterRange - jitterRange/2) // Random value between -jitterRange/2 and +jitterRange/2
	
	// Calculate final sleep duration
	finalDuration := baseDuration + jitter
	
	// Ensure the duration is positive
	if finalDuration < 0 {
		finalDuration = baseDuration
	}
	
	time.Sleep(finalDuration)
}

// SleepWithExponentialBackoff sleeps with exponentially increasing delays and jitter
func SleepWithExponentialBackoff(baseDuration time.Duration, attempt int, maxDuration time.Duration) {
	// Calculate exponential delay
	expDelay := baseDuration * (1 << uint(attempt)) // 2^attempt
	
	// Add jitter
	jitter := time.Duration(rand.Float64() * float64(expDelay) * 0.1) // +/- 10% jitter
	finalDuration := expDelay + jitter
	
	// Cap at maximum duration
	if finalDuration > maxDuration {
		finalDuration = maxDuration
	}
	
	time.Sleep(finalDuration)
}

// FoliageStyleSleep implements a more sophisticated sleep pattern
// This mimics the "Foliage" technique to evade sandbox timing checks
func FoliageStyleSleep(baseDuration time.Duration) {
	// Break the sleep into smaller chunks with variable timing
	totalSleep := int64(baseDuration)
	chunkSize := int64(100 * time.Millisecond) // 100ms chunks
	
	// Randomize the chunk size slightly
	chunkVariance := int64(20 * time.Millisecond) // +/- 20ms variance
	
	for totalSleep > 0 {
		// Calculate current chunk size with variance
		currentChunk := chunkSize
		if rand.Float32() > 0.5 {
			currentChunk += int64(rand.Float64() * float64(chunkVariance))
		} else {
			currentChunk -= int64(rand.Float64() * float64(chunkVariance/2))
		}
		
		// Ensure we don't sleep longer than remaining time
		if currentChunk > totalSleep {
			currentChunk = totalSleep
		}
		
		time.Sleep(time.Duration(currentChunk))
		totalSleep -= currentChunk
	}
}