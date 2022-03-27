package webhost

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/mux"
)

type WebHost interface {
	GetConfig() Config
	Run()
}

type webHost struct {
	config     Config
	httpRouter *mux.Router
	httpServer *http.Server
}

func NewWebHost(r *mux.Router) WebHost {
	host := &webHost{
		config:     NewConfig(),
		httpRouter: r,
	}
	return host
}

func (host *webHost) GetConfig() Config {
	return host.config
}

func (host *webHost) Run() {
	// Start the http server
	host.startHttpServer()

	// Wait for cancel signal (CTRL+C)
	cancelSignal := make(chan os.Signal, 1)
	signal.Notify(cancelSignal, os.Interrupt)
	<-cancelSignal

	// Stop the http server
	host.stopHttpServer()
}

func (host *webHost) startHttpServer() {
	// Create the http server
	httpServerAddress := host.config.GetHttpBind() + ":" + host.config.GetHttpPort()
	host.httpServer = &http.Server{
		Handler:      host.httpRouter,
		Addr:         httpServerAddress,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	// Run our server in a goroutine so that it doesn't block.
	log.Printf("Starting http server (Address: %s)\n", host.httpServer.Addr)
	go func() {
		if err := host.httpServer.ListenAndServe(); err != nil {
			if err == http.ErrServerClosed {
				// Ignore
			} else {
				log.Fatalf("Server failed to run: %v", err)
			}
		}
	}()
}

func (host *webHost) stopHttpServer() {
	log.Printf("Stopping http server")

	// Create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	host.httpServer.Shutdown(ctx)
}
