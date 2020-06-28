package db

import (
	"database/sql"
	_ "github.com/go-sql-driver/mysql" // mysql driver
	"time"

	"github.com/dandelabs/ghostbuster-backend-libs/dandelog"
)

var dbCon *sql.DB

// StartDBCon initialize DB connection
func StartDBCon(dbURL string) error {
	method := "StartDBCon:"
	var err error
	if dbCon == nil {

		dbCon, err = sql.Open("mysql", dbURL)
		if err != nil {
			dandelog.Error.Fatal(method + err.Error())
			panic(err)
		}
		dbCon.SetConnMaxLifetime(time.Minute * 10)
		dbCon.SetMaxOpenConns(20)

	}
	return err
}
