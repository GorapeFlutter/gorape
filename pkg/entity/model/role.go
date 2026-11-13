package model

type Role string

const (
	RoleViewer Role = "viewer"
	RoleEditor Role = "editor"
	RoleAdmin  Role = "admin"
)

func (rcvr Role) Valid() bool { return rcvr == RoleViewer || rcvr == RoleEditor || rcvr == RoleAdmin }
func (rcvr Role) Rank() int {
	switch rcvr {
	case RoleAdmin:
		return 3
	case RoleEditor:
		return 2
	case RoleViewer:
		return 1
	}
	return 0
}
