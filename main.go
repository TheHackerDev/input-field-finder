// Package main contains the main functionality of the program.
// This program spiders a given domain and returns the input fields
// found in the responses.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// HTTP client that ignores TLS errors
var client = http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	},
}

// Visited tracks visited URLs, to avoid redundancy & loops
type Visited struct {
	URLS  map[string]bool
	mutex sync.RWMutex
}

var visited Visited

// Whitelist is a group of targets that are allowed to be spidered and searched.
// Targets can be either domains or IP addresses, and must contain the scheme (http or https, in this case). Example: http://www.example.com or https://127.0.0.1:8080
type Whitelist struct {
	Targets []*url.URL
}

var whitelist Whitelist

// Create the channels used to pass URLs found during spidering
// Make it a really high value, to prevent blocking on the pipe
var urlQueue = make(chan *url.URL, 1000000)

// The command-line flags
var flagStartURL = flag.String("url", "", "[REQUIRED] `URL` to start spidering from. The domain and scheme will be used as the whitelist.") // TODO: Allow multiple URLs, comma-separated.

// Function main is the entry point for the application. It parses the flags
// provided by the user and calls the router function for any URLs
// passed into the URL queue.
func main() {
	// Change output location of logs (TEMP)
	log.SetOutput(os.Stdout)

	// Configure the usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprint(os.Stderr, "  --help: Displays this message\n")
		flag.PrintDefaults()
		fmt.Fprint(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "\t%s -url=http://www.example.com/\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\t%s -url=https://www.example.com/\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\t%s -url=http://127.0.0.1/\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\t%s -url=http://127.0.0.1:8080/\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\t%s -url=http://www.example.com/example/\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\t%s -url=http://www.example.com/example/page/1?id=2#heading\n", os.Args[0])
	}

	// Parse the command-line flags provided
	flag.Parse()

	// Ensure that we have required flags
	if *flagStartURL == "" {
		// Default value provided
		flag.Usage()
		os.Exit(1)
	}

	// Set up the visited URLs
	visited = Visited{
		URLS: make(map[string]bool),
	}

	// Check if the start URL is valid
	startURLvalue, err := url.Parse(*flagStartURL)
	if err != nil || startURLvalue.String() == "" {
		log.Println("Invalid URL provided.")
		flag.Usage()
		os.Exit(1)
	}

	// Remove hashes from the URL
	startURLvalue.Fragment = ""

	// Add the starting URL to the whitelist
	whitelist = Whitelist{Targets: []*url.URL{startURLvalue}}

	// Add the starting URL to the queue
	addURL(startURLvalue)

	// Keep working as long as there are URLs in the queue
	for len(urlQueue) > 0 {
		// Start working on the next URL in the queue
		dataRouter(<-urlQueue)

	}
}

// Function dataRouter requests the given URL, and passes it to various helper functions.
// It returns any errors it receives throughout this process.
// Output functionality currently occurs in the helper functions.
func dataRouter(urlValue *url.URL) (err error) {
	// Set up a wait group for concurrency
	var wg sync.WaitGroup

	// Get the first URL's document body
	response, err := client.Get(urlValue.String())
	if err != nil {
		log.Printf("[ERROR] [%s] %s\n", urlValue.String(), err.Error())
		return
	}
	defer response.Body.Close() // Make sure the response gets closed
	document, err := html.Parse(response.Body)
	if err != nil {
		log.Printf("[ERROR] [%s] %s\n", urlValue.String(), err.Error())
		return
	}

	// Run the spidering function on the html document
	wg.Add(1)
	go func() {
		getAnchors(document, urlValue)
		wg.Done()
	}()

	// Search for input fields in the html document
	wg.Add(1)
	go func() {
		getInputs(document, urlValue)
		wg.Done()
	}()

	// Wait for all the concurrent processes to finish
	wg.Wait()

	return
}

// Function getAnchors parses out the links from anchor elements found in the
// provided HTML node.
// It uses the provided worker pool to perform the task concurrently for the calling function,
// returning a worker back to the pool upon completion.
// urlValue is the current URL that it is working with; this is used for contextual logging.
func getAnchors(document *html.Node, currentURL *url.URL) {
	// Recursively search the document tree for anchor values
	var nodeSearch func(*html.Node)
	nodeSearch = func(node *html.Node) {
		if node.Type == html.ElementNode && node.DataAtom == atom.A {
			// We've found an anchor tag, get the href value
			for _, attribute := range node.Attr {
				if attribute.Key == "href" {

					// Check for useless links
					if attribute.Val == "#" || attribute.Val == "" {
						continue
					}

					// Make sure it's a valid URL
					urlValue, err := url.Parse(attribute.Val)
					if err != nil || urlValue.String() == "" {
						log.Printf("[ERROR] [%s] Error parsing URL: %s\n", currentURL.String(), attribute.Val)
						continue
					}

					// Check for relative URLs
					if urlValue.Scheme == "" && urlValue.String()[:1] == "/" {
						// Path relative to root domain, add the appropriate scheme and domain
						urlValue.Scheme = currentURL.Scheme
						urlValue.Host = currentURL.Host
					} else if urlValue.Scheme == "" && urlValue.String()[:2] == "//" {
						// Path relative to scheme, add the appropriate scheme
						urlValue.Scheme = currentURL.Scheme
					}

					// Add the link to the list
					addURL(urlValue)
				}
			}
		}
		// recurse down the tree
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			nodeSearch(child)
		}

	}

	nodeSearch(document)
}

// Function addURL simply adds a URL to the URL queue, if it has
// not already been visited.
func addURL(urlValue *url.URL) {
	// Make sure the URL is in the whitelisted domains list
	if isWhitelisted(urlValue) {
		// Rebuild the url string, removing any hashes from the link
		urlValue.Fragment = ""
		urlString := urlValue.String()

		// Check for trailing slash
		// TODO: Optimize
		var urlStringNoSlash string
		if strings.HasSuffix(urlString, "/") {
			urlStringNoSlash = urlString[:len(urlString)-1]
		} else {
			urlStringNoSlash = urlString
		}

		// Make sure the URL has not been visited
		visited.mutex.Lock()
		defer visited.mutex.Unlock()
		_, exists := visited.URLS[urlString]
		_, existsNoSlash := visited.URLS[urlStringNoSlash]
		if !exists && !existsNoSlash {
			// Add the URL to visited now, to prevent race issues
			visited.URLS[urlValue.String()] = true
			// Add the URL to the queue
			urlQueue <- urlValue
		}
	}
	return
}

// Function isWhitelisted checks if a provided URL is on the whitelist.
func isWhitelisted(urlValue *url.URL) (whitelisted bool) {
	// Assume false
	whitelisted = false

	// Check scheme & host against whitelisted values
	for _, target := range whitelist.Targets {
		if strings.ToLower(urlValue.Scheme) == strings.ToLower(target.Scheme) && strings.ToLower(urlValue.Host) == strings.ToLower(target.Host) {
			// URL is whitelisted
			whitelisted = true
			return
		}
	}

	return
}

// Function getInputs parses out the input elements from the provided HTML node.
// It uses the worker pool to perform the task concurrently from the calling function,
// returning the worker to the pool upon completion.
// urlValue is the current URL that it is working with; this is used for contextual logging.
func getInputs(document *html.Node, urlValue *url.URL) {
	// Create a slice to hold all the input fields for the current URL
	var inputs []string

	// Recursively search the document tree for input fields
	var nodeSearch func(*html.Node)
	nodeSearch = func(node *html.Node) {
		if node.Type == html.ElementNode && node.DataAtom == atom.Input {
			// We've found an input tag
			// Recreate the input code
			var input = "<input "
			for _, attribute := range node.Attr {
				input = input + fmt.Sprintf(" %s=\"%s\"", attribute.Key, attribute.Val)
			}
			input = input + "></input>"

			// Remove newline characters
			cleanInput := strings.Replace(input, "\n", "", -1)

			// Add the input tag to the inputs slice
			inputs = append(inputs, cleanInput)
		}
		// recurse down the tree
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			nodeSearch(child)
		}
	}
	nodeSearch(document)

	// Output the input elements found on the current URL, if any are found
	if len(inputs) > 0 {
		fmt.Printf("[%s]\n", urlValue.String())
		for _, input := range inputs {
			fmt.Printf("\t%s\n", input)
		}
		// Extra line for spacing
		fmt.Println()
	}
}

// TODO: Add in the option for verbose logging (all URLs spidered for basic verbosity, and when it reaches spidering/input finding functions in double verbosity)
// TODO: Find optimal value for URLQueue size
