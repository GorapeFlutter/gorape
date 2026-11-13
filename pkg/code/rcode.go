package code

// RCode represents a response code
type RCode struct {
	Code    string
	Message string
}

// Controller Response Codes - User Public
var (
	// Create User
	UCPCU001 = RCode{"SERVER_CONTROLLER_CREATE__FOR__001", "Bind request failed"}
	UCPCU002 = RCode{"SERVER_CONTROLLER_CREATE__FOR__002", "Required fields missing"}
	UCPCU003 = RCode{"SERVER_CONTROLLER_CREATE__FOR__003", "Email already exists"}
	UCPCU004 = RCode{"SERVER_CONTROLLER_CREATE__FOR__004", "Password hash failed"}
	UCPCUSUC = RCode{"SUCCESS", "User created successfully"}

	// Get Users
	UCPGU001 = RCode{"SERVER_CONTROLLER_GET__FOR__001", "Bind request failed"}
	UCPGUSUC = RCode{"SUCCESS", "Users retrieved successfully"}
)
