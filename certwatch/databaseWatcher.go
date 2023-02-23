package certwatch

import (
	"context"
	"sync"
)

var databaseWatcherMutex sync.Mutex

func DatabaseWatcherPing() error {
	databaseWatcherMutex.Lock()
	err := connDatabaseWatcher.Ping(context.Background())
	databaseWatcherMutex.Unlock()
	return err
}
