package main

// Embedded icon assets (shared by the native window and the tray icon).

import _ "embed"

//go:embed icons/on.ico
var iconOn []byte

//go:embed icons/off.ico
var iconOff []byte

//go:embed icons/app.ico
var iconApp []byte
