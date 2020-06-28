package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/dandelabs/ghostbuster-backend-libs/crypt"
	"github.com/dandelabs/ghostbuster-backend-libs/dandelog"
	"strconv"
)

const (
	StateUserActive   = "ACTIVE"
	StateUserInactive = "INACTIVE"
)

// User struct stores all user information
type User struct {
	UserId    string
	FirstName string `sql:"first_name" json:"first_name"`
	LastName  string `sql:"last_name" json:"last_name"`
	NickName  string `sql:"nick_name" json:"nick_name"`
	Password  string
}

type UserMachine struct {
	User     *User
	Machines []*string
}

func InsertUser(userMachine UserMachine) (id int64, err error) {
	method := "insertUser:"
	dandelog.Trace.Println(method)
	out, err := json.Marshal(userMachine)
	dandelog.Trace.Println("UserMachine:" + string(out))
	var userID int64
	var result sql.Result

	hash, salt, err := crypt.GenerateEncryptPassword(userMachine.User.Password)
	if err != nil {
		return userID, err
	}

	result, err = dbCon.Exec("INSERT INTO pfoptimization.users(first_name, "+
		" last_name, nick_name, password, salt, created, updated, state) "+
		" VALUES(?,?,?,?,?, (UNIX_TIMESTAMP(now())), "+
		"(UNIX_TIMESTAMP(now())), ?)",
		userMachine.User.FirstName, userMachine.User.LastName, userMachine.User.NickName, hash, salt, StateUserActive)
	if err == nil {
		userID, err = result.LastInsertId()
		if err == nil {
			nRows, err := result.RowsAffected()
			dandelog.Info.Println(method+"number of user created%d", nRows)
			if nRows == 0 || err != nil {
				err = errors.New("New users were not inserted")
				return 0, err
			} else {
				for _, machine := range userMachine.Machines {
					dandelog.Info.Println("UserID:" + strconv.FormatInt(userID, 10) + " Manchine_ID:" + *machine)
					result, err = dbCon.Exec("INSERT INTO pfoptimization.machine_user(user_id, "+
						" machine_id) "+
						" VALUES(?,?) ", userID, machine)
					if err != nil {
						dandelog.Error.Print(method + err.Error())
						return userID, err
					}
				}

			}
		} else {
			dandelog.Error.Print(method + err.Error())
			return 0, err
		}

	} else {
		dandelog.Error.Print(method + err.Error())
		return 0, err
	}

	return userID, err
}

func ValidateLogin(nickname string, password string) (bool, string, error) {
	method := "validateLogin:"
	dandelog.Trace.Print("nickname:" + nickname)
	iterations := 4096
	keySize := 32
	var salt []byte
	var hash []byte
	var id string
	var state string
	match := false

	err := dbCon.QueryRow("SELECT u.password, u.salt, u.user_id, u.state "+
		" FROM pfoptimization.users u "+
		" WHERE u.nick_name = ? ", nickname).Scan(&hash, &salt, &id, &state)

	if err == nil {
		if state == "INACTIVE" {
			err = errors.New("The user is INACTIVE")
		} else {
			dandelog.Info.Println(method, "VALIDATE PASSWORD", iterations, keySize)
			match = crypt.ValidatePassword(password, salt, hash, iterations, keySize)
			dandelog.Trace.Println(method+"result validation :%t:id:"+id, match)
		}
	} else {
		dandelog.Error.Print(method + err.Error())
	}
	return match, id, err
}

func ValidateUserMachine(nickname string, machineId string) (bool, error) {
	method := "ValidateUserMachine:"
	dandelog.Trace.Print("nickname:" + nickname)

	var id string

	err := dbCon.QueryRow("SELECT mu.machine_user_id "+
		" FROM pfoptimization.machine_user mu  "+
		"	LEFT JOIN (pfoptimization.users u, pfoptimization.machines m) "+
		"	ON (u.user_id = mu.user_id AND m.machine_id = mu.machine_id) "+
		" WHERE u.nick_name = ? "+
		" AND m.machine_id = ?"+
		" AND machine_active = ?", nickname, machineId,
		StateMachineActive).Scan(&id)

	if err != nil {
		dandelog.Error.Print(method + err.Error())
		return false, err
	}
	return true, err
}
