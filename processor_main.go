package main

import (
	"database/sql"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"github.com/BurntSushi/toml"
	_ "github.com/lib/pq"
)

type duration struct {
	time.Duration
}

func (d *duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(text))
	return err
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func recoverErr(context string) {
	if r := recover(); r != nil {
		log.Printf("ERROR: %v [%s]", r, context)
	}
}

func doUpdateWorkItem(wi *WorkItem, update_statement *sql.Stmt) {
	result, err := wi.Update(update_statement)
	if err != nil {
		log.Printf("ERROR: Update() failed (%v)\n", err)
	} else if result != nil {
		rows_affected, err := result.RowsAffected()
		if err != nil {
			log.Printf("ERROR: Update() failed (%v)\n", err)
		} else if rows_affected < 1 {
			log.Println("ERROR: No rows affected")
		}
	}
}

func doBatchOfWork(db *sql.DB, w *Work, batch_size int, concurrent_items int) int {
	// Fetch a batch of work to do from the DB
	w.Begin(db)
	select_query := w.SelectQuery(batch_size)
	rows, err := db.Query(select_query)
	checkErr(err)
	defer rows.Close()

	// Prepare the UPDATE statement that will be run after performing each work item
	var update_statement *sql.Stmt
	if w.UpdateStatement() != "" {
		update_statement, err = db.Prepare(w.UpdateStatement())
		checkErr(err)
		defer update_statement.Close()
	}

	// Do the batch of work, throttling the number of concurrent work items
	var wg sync.WaitGroup
	var chan_concurrency = make(chan int, concurrent_items)
	var i int
	for i = 0; rows.Next(); i++ {
		var wi WorkItem
		err = wi.Parse(rows)
		checkErr(err)
		wg.Add(1)
		go func() {
			defer func() {
				wg.Done()
			}()
			defer doUpdateWorkItem(&wi, update_statement)
			chan_concurrency <- 1
			defer func() { <-chan_concurrency }()
			defer recoverErr("recoverErr")
			wi.Perform(db, w)
		}()
	}

	// Wait for all work items to complete
	wg.Wait()
	w.End()

	return i
}

var build_date string
var svn_revision string

func main() {
	defer recoverErr("main")

	// Don't log the date and time, because daemontools does this for us.
	log.SetFlags(0)

	// Configure signal handling
	chan_signals := make(chan os.Signal, 20)
	signal.Notify(chan_signals, os.Interrupt, syscall.SIGTERM)

	// Read configuration file
	config_filename := (os.Args[0][(strings.LastIndex(os.Args[0], "/") + 1):len(os.Args[0])]) + ".toml"
	var c config
	if _, err := toml.DecodeFile(config_filename, &c); err != nil {
		config_filename = "default.toml"
		if _, err = toml.DecodeFile(config_filename, &c); err != nil {
			panic(err)
		}
	}

	// Parse common command line flags
	flag.StringVar(&c.ConnInfo, "conninfo", c.ConnInfo, "DB connection info")
	flag.IntVar(&c.ConnOpen, "connopen", c.ConnOpen, "Maximum number of open connections to the DB [0=unlimited]")
	flag.IntVar(&c.ConnIdle, "connidle", c.ConnIdle, "Maximum number of connections in the idle connection pool")
	flag.DurationVar(&c.ConnLife.Duration, "connlife", c.ConnLife.Duration, "Maximum amount of time a connection may be reused [0=reuse forever]")
	flag.DurationVar(&c.Interval.Duration, "interval", c.Interval.Duration, "How often to check for more work [0=exit when no more work to do]")
	flag.IntVar(&c.Batch, "batch", c.Batch, "Maximum number of items per batch of work")
	flag.IntVar(&c.Concurrent, "concurrent", c.Concurrent, "Maximum number of items processed simultaneously")
	var check_config bool
	flag.BoolVar(&check_config, "checkconfig", false, "Check configuration then exit")
	c.DefineCustomFlags()
	flag.Parse()

	// Show configuration
	log.Printf("[%s | r%s | %s] baseconfigfile:%s conninfo:%s connopen:%d connidle:%d connlife:%v interval:%v batch:%d concurrent:%d %s", os.Args[0][(strings.LastIndex(os.Args[0], "/") + 1):len(os.Args[0])], svn_revision, strings.Replace(build_date, ".", " ", 1), config_filename, c.ConnInfo, c.ConnOpen, c.ConnIdle, c.ConnLife.Duration, c.Interval.Duration, c.Batch, c.Concurrent, c.PrintCustomFlags())

	// Check configuration
	if c.ConnInfo == "" {
		panic(errors.New("No connection info specified!"))
	} else if c.ConnOpen == 1 {
		panic(errors.New("At least 2 open connections are required!"))
	}

	// Connect to the database
	db, err := sql.Open("postgres", c.ConnInfo)
	checkErr(err)
	defer db.Close()
	db.SetMaxOpenConns(c.ConnOpen)
	db.SetMaxIdleConns(c.ConnIdle)
	db.SetConnMaxLifetime(c.ConnLife.Duration)

	// Perform work in batches
	var work Work
	work.db = db
	work.Init(&c)
	next_time := time.Now()
	keep_looping := true
	if check_config {
		err = db.Ping()
		checkErr(err)
	} else {
		for keep_looping {
			// Perform one batch of work
			items_processed := doBatchOfWork(db, &work, c.Batch, c.Concurrent)

			// Exit if interval=0s and there's no more work to do
			if (items_processed == 0) && (c.Interval.Duration == 0) {
				break
			}

			// Schedule the next batch of work
			next_time = next_time.Add(c.Interval.Duration)
			if (items_processed > 0) || (next_time.Before(time.Now())) {
				next_time = time.Now()
			}

			// Have a rest if possible.  Process any pending SIGINT or SIGTERM.
			select {
				case sig := <-chan_signals:
					log.Printf("Signal received: %v\n", sig)
					keep_looping = false
				case <-time.After(next_time.Sub(time.Now())):
			}
		}
	}

	// We're done
	work.Exit()
	log.Println("Goodbye!")
}
