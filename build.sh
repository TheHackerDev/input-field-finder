#!/bin/bash

# Clean previous installs
rm -rf ~/Desktop/input-field-finder/*

# WINDOWS
GOOS=windows GOARCH=amd64 go build -o ~/Desktop/input-field-finder/input-field-finder_v1.1.0_win64.exe .
GOOS=windows GOARCH=386 go build -o ~/Desktop/input-field-finder/input-field-finder_v1.1.0_win32.exe .
echo "Windows complete"

# OSX
GOOS=darwin GOARCH=amd64 go build -o ~/Desktop/input-field-finder/input-field-finder_v1.1.0_osx64.app .
zip -q ~/Desktop/input-field-finder/input-field-finder_v1.1.0_osx64.app.zip ~/Desktop/input-field-finder/input-field-finder_v1.1.0_osx64.app
rm ~/Desktop/input-field-finder/input-field-finder_v1.1.0_osx64.app
GOOS=darwin GOARCH=386 go build -o ~/Desktop/input-field-finder/input-field-finder_v1.1.0_osx32.app .
zip -q ~/Desktop/input-field-finder/input-field-finder_v1.1.0_osx32.app.zip ~/Desktop/input-field-finder/input-field-finder_v1.1.0_osx32.app
rm ~/Desktop/input-field-finder/input-field-finder_v1.1.0_osx32.app
echo "OSX complete"

# LINUX
GOOS=linux GOARCH=amd64 go build -o ~/Desktop/input-field-finder/input-field-finder_v1.1.0_lin64.bin .
GOOS=linux GOARCH=386 go build -o ~/Desktop/input-field-finder/input-field-finder_v1.1.0_lin32.bin .
echo "Linux complete"
