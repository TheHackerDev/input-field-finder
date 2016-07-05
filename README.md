# input-field-finder

Spiders a given URL's entire domain and prints out all `<input>` elements found on the given domain and scheme (http/https).

## Why?

Input fields are the most common vector/sink for web application vulnerabilities. I wrote this tool to help automate the reconnaissance phase when testing web applications for security vulnerabilities.

## Usage

This is a command-line tool. Use the following flags to run the program:

- `-urls`: URL or comma-separated list of URLs to search. The domain and scheme will be used as the whitelist.
- `-url-file`: The location (relative or absolute path) of a file of newline-separated URLs to search.
- `-v`: Enable verbose logging to the console.
- `-vv`: Enable doubly-verbose logging to the console.

**Examples**:

- `input-field-finder -urls=http://www.example.com/`: Searches `www.example.com` using the `http` scheme.
- `input-field-finder -urls=https://www.example.com/`: Searches `www.example.com` using the `https` scheme.
- `input-field-finder -urls=http://127.0.0.1/`: Searches `127.0.0.1` using the `http` scheme.
- `input-field-finder -urls=http://127.0.0.1:8080/`: Searches `127.0.0.1` using the `http` scheme, on port 8080.
- `input-field-finder -urls=http://127.0.0.1,http://www.example.com`: Searches `127.0.0.1` and `www.example.com` using the `http` scheme, on port 8080.
- `input-field-finder -url-file=/root/urls.txt`: Searches the URLs found in the file located at the absolute path of `/root/urls.txt`.
- `input-field-finder -url-file=urls.txt`: Searches the URLs found in the `url.txt` file located in the current directory.
- `input-field-finder -v -urls=http://www.example.com/example/`: Searches `www.example.com` using the `http` scheme, starting at the `/example/` path, with verbose logging.
- `input-field-finder -vv -urls=http://www.example.com/example/page/1?id=2#heading`: Searches `www.example.com` using the `http` scheme, starting at the `/example/page/1` path, with a query of `id=2`, the `#heading` URL fragment, with verbose logging.

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

1. ~~Ability to pass multiple URLs in the `-url` flag.~~
2. Ability to pass in a file of URLs.
3. Option to search all subdomains found during spidering as well.
4. Support for single-page applications (SPA), by rendering JavaScript in pages, and THEN parsing the responses.
5. "Cookie jar" functionality for authenticated scans.
