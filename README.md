# 🔍 NimSQL Scanner

## ✨ Features

- 🚀 Asynchronous
- 💉 Helps do enumeration of SQL prompts for injection
- 🛡️ Can be used to scan for SQL injection vulnerabilities

## 🔧 Installation

```bash
nim c -r src/scanner.nim
```

## 📖 Usage

```bash
./nimsqli --method=GET -p id -d 10 "http://www.example.com/page.php?id=1"
```

### Required Parameters:
- `-p <parameter>`: 🎯 Specify which parameter to test (e.g., `-p id`)
- `--method=<METHOD>`: 📡 HTTP method to use (GET or POST)
- `-d <delay>`: ⏱️ Delay between requests in milliseconds
- URL: 🔗 The target URL to test

Example:
```bash
# Testing the 'id' parameter with 10ms delay
./nimsqli --method=GET -p id -d 10 "http://www.example.com/page.php?id=1"
```

## 🚧 COMING UP

- 🔄 Expanding SQLi methods
- 📁 Reading SQLi methods from file
- 📋 Reading URLs from file
- 🎨 Adding colors to the output
- ⏳ Adding progress bar
- 📊 Adding report output
- 💾 Adding database output
