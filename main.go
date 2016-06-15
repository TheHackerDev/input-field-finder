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

// Visited tracks visited URLs, to avoid redundancy & loops
type Visited struct {
	URLS  map[string]bool
	mutex sync.Mutex
}

var visited Visited

// Whitelist is a group of targets that are allowed to be spidered and
// searched.
// Targets can be either domains or IP addresses, and must contain the scheme (http or https, in this case). Example: http://www.example.com or https://127.0.0.1:8080
type Whitelist struct {
	Targets []*url.URL
}

var whitelist Whitelist

// Create the worker pool, used to set the upper limit & track the number of workers in use.
var workerPool chan struct{}
var maxWorkers int // Upper limit of workers

// Create the channels used to pass URLs found during spidering
// TODO: Find the optimal size of buffer.
var urlQueue = make(chan *url.URL, 100) // arbitrary buffer size, increase for more performance

// The command-line flags
var flagStartURL = flag.String("url", "", "[REQUIRED] `URL` to start spidering from. The domain and scheme will be used as the whitelist.") // TODO: Allow multiple URLs, comma-separated.
var flagConcurrency = flag.Uint("concurrency", 3, "Level of concurrency. `0-5`; higher is faster (network requests & processing), 0 for no concurrency. Default: 3")

// Function main is the entry point for the application. It parses the flags
// provided by the user and calls the router function for any URLs
// passed into the URL queue.
func main() {
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
		fmt.Fprintf(os.Stderr, "\t%s -concurrency=5 -url=https://www.example.com/\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\t%s -concurrency=0 -url=http://www.example.com/\n", os.Args[0])
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

	// Configure the max workers based on the level chosen by the user
	switch *flagConcurrency {
	case 0:
		// No concurrency
		maxWorkers = 1
	case 1:
		// Lowest level of concurrency
		maxWorkers = 5
	case 2:
		// Low level of concurrency
		maxWorkers = 10
	case 4:
		// High level of concurrency
		maxWorkers = 50
	case 5:
		// Highest level of concurrency
		maxWorkers = 100
	default:
		// Medium level of concurrency (-concurrency=3)
		maxWorkers = 20
	}

	// Initialize the worker pool
	workerPool = make(chan struct{}, maxWorkers)
	// Fill the worker pool
	for i := 0; i < maxWorkers; i++ {
		workerPool <- struct{}{}
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

	// Add the starting URL to the whitelist and queue
	whitelist = Whitelist{Targets: []*url.URL{startURLvalue}}
	urlQueue <- startURLvalue

	// Keep working as long as there are workers working or URLs in the queue
	for len(workerPool) < maxWorkers || len(urlQueue) > 0 {
		// If there are URLs available, work with it
		if len(urlQueue) > 0 {
			// Take a worker from the pool
			<-workerPool
			// Pass a URL to the router, concurrently
			go dataRouter(<-urlQueue) // TODO: Handle errors
		}
	}
}

// Function dataRouter requests the given URL, and passes it to various helper functions.
// It returns any errors it receives throughout this process.
// Output functionality currently occurs in the helper functions.
func dataRouter(urlValue *url.URL) (err error) {
	// Ensure that the worker goes back in the pool before returning
	defer func() {
		workerPool <- struct{}{}
	}()

	// Remove hashes from the URL
	urlValue.Fragment = ""

	// Ensure we haven't visited the URL before
	if _, exists := visited.URLS[urlValue.String()]; exists {
		// Has already been visited
		return
	}

	// Set up an internal worker queue for concurrency
	internalQueue := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		internalQueue <- struct{}{}
	}

	// Configure HTTP client that ignores TLS errors
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := http.Client{
		Transport: transport,
	}

	// Get the first URL's document body
	response, err := client.Get(urlValue.String())
	if err != nil {
		return
	}
	defer response.Body.Close() // Make sure the response gets closed
	document, err := html.Parse(response.Body)
	if err != nil {
		return
	}

	// Run the spidering function on the html document
	<-internalQueue
	go getAnchors(document, urlValue, internalQueue)

	// Search for input fields in the html document
	<-internalQueue
	go getInputs(document, urlValue, internalQueue)

	// Don't return until all goroutines have completed
	<-internalQueue // One for spider function
	<-internalQueue // One for input finder function

	// Add the URL to the visited list, safely
	visited.mutex.Lock()
	defer visited.mutex.Unlock()
	visited.URLS[urlValue.String()] = true

	return
}

// Function getAnchors parses out the links from anchor elements found in the
// provided HTML node.
// It uses the provided worker pool to perform the task concurrently for the calling function,
// returning a worker back to the pool upon completion.
// urlValue is the current URL that it is working with; this is used for contextual logging.
func getAnchors(document *html.Node, currentURL *url.URL, pool chan struct{}) {
	// Make sure the workers are returned to the worker pool
	defer func() {
		pool <- struct{}{}
	}()

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

		// Make sure the URL has not been visited
		if _, exists := visited.URLS[urlString]; !exists {
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
func getInputs(document *html.Node, urlValue *url.URL, pool chan struct{}) {
	// Make sure the workers are returned to the worker pool
	defer func() {
		pool <- struct{}{}
	}()

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
