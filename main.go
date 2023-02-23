/* crt.sh: ct_monitor - Certificate Transparency Log Monitor
 * Written by Rob Stradling
 * Copyright (C) 2015-2023 Sectigo Limited
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package main

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/crtsh/ct_monitor/certwatch"
	"github.com/crtsh/ct_monitor/ct"
	"github.com/crtsh/ct_monitor/logger"
	"github.com/crtsh/ct_monitor/msg"
	"github.com/crtsh/ct_monitor/server"
)

func main() {
	// The certwatch database connections, which were opened automatically by the init() function, need to be closed on exit.
	defer certwatch.Close()

	// Configure graceful shutdown capabilities.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	defer msg.ShutdownWG.Wait()

	// Start the N goroutines.
	msg.ShutdownWG.Add(3)
	go certwatch.LogConfigSyncer(ctx)
	go ct.GetEntriesLauncher(ctx)
	go certwatch.NewEntriesWriter(ctx)

	// Start the Monitoring HTTP server.
	server.Run()
	defer server.Shutdown()

	// Wait to be interrupted.
	<-ctx.Done()

	// Ensure all log messages are flushed before we exit.
	logger.Logger.Sync()
}
