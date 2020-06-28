package db

import (
	"github.com/dandelabs/ghostbuster-backend-libs/dandelog"
)

const (
	StateMachineActive   = "ACTIVE"
	StateMachineInactive = "INACTIVE"
)

// User struct stores all user information
type Machine struct {
	MachineId           string `sql:"machine_id" json:"machine_id"`
	MachineName         string `sql:"machine_name" json:"machine_name"`
	StatusIdPrimaryRm   string `sql:"status_id_primary_rm" json:"status_id_primary_rm,omitempty"`
	StatusIdSecondaryRm string `sql:"status_id_secondary_rm" json:"status_id_secondary_rm,omitempty"`
	MachineActive       string `sql:"machine_active" json:"machine_active,omitempty"`
}

func GetMachines() ([]*Machine, error) {
	method := "GetMachines:"
	dandelog.Trace.Println(method)
	var result []*Machine
	rows, err := dbCon.Query(" SELECT m.machine_id,m.machine_name "+
		" FROM pfoptimization.machines m "+
		" WHERE  machine_active = ? ", StateMachineActive)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		machine := new(Machine)
		rows.Scan(&machine.MachineId, &machine.MachineName)
		result = append(result, machine)
	}
	return result, err
}
