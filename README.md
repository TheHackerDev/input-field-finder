# input-field-finder
Spiders a given URL's entire domain and prints out all `<input>` elements found on the given domain and scheme (http/https).

## Why?
Input fields are the most common vector/sink for web application vulnerabilities. I wrote this tool to help automate the reconnaissance phase when testing web applications for security vulnerabilities.

## Usage
This is a command-line tool. Use the following flags to run the program:
- `-url`: (Required) This is the URL to start spidering from. The domain and scheme will be used as the whitelist for targets to spider.
- `-v`: Enable verbose logging to the console.
- `-vv`: Enable doubly-verbose logging to the console.

**Examples**:
- `input-field-finder -url=http://www.example.com/`: Searches `www.example.com` using the `http` scheme.
- `input-field-finder -url=https://www.example.com/`: Searches `www.example.com` using the `https` scheme.
- `input-field-finder -url=http://127.0.0.1/`: Searches `127.0.0.1` using the `http` scheme.
- `input-field-finder -url=http://127.0.0.1:8080/`: Searches `127.0.0.1` using the `http` scheme, on port 8080.
- `input-field-finder -v -url=http://www.example.com/example/`: Searches `www.example.com` using the `http` scheme, starting at the `/example/` path, with verbose logging.
- `input-field-finder -vv -url=http://www.example.com/example/page/1?id=2#heading`: Searches `www.example.com` using the `http` scheme, starting at the `/example/page/1` path, with a query of `id=2`, the `#heading` URL fragment, with verbose logging.

## Binaries
The program has been written in Go, and as such can be compiled to all the common platforms in use today. The following architectures have been compiled, and can be found in the [releases](https://github.com/insp3ctre/input-field-finder/releases) tab:
- Windows amd64
- Windows 386
- Linux amd64
- Linux 386
- OSX amd64
- OSX 386

Alternatively, you can compile the code yourself. See [Dave Cheney](https://twitter.com/davecheney)'s excellent [post](http://dave.cheney.net/2015/08/22/cross-compilation-with-go-1-5 "Cross-compilation with Go 1.5") on the topic.

## Planned Improvements
- Add the ability to pass multiple URLs in the `-url` flag
- Add the ability to pass in a file of URLs
