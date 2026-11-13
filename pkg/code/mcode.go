package code

import "strings"

// MCode represents a message code with its description
type MCode struct {
	Code    string
	Message string
}

// PaddedCode returns the code padded to maxCodeLength for aligned log output
func (rcvr MCode) PaddedCode() string {
	if len(rcvr.Code) >= maxCodeLength {
		return rcvr.Code
	}
	return rcvr.Code + strings.Repeat(" ", maxCodeLength-len(rcvr.Code))
}

// GetMaxCodeLength returns the current maximum code length
func GetMaxCodeLength() int {
	return maxCodeLength
}

var maxCodeLength int

// calculateMaxCodeLength calculates the maximum code length from all defined codes
func calculateMaxCodeLength() int {
	codes := []MCode{
		// System codes
		SM1, SM2, SM3,

		// Middleware Logger With Config codes
		MLWC1, MLWC2, MLWC3, MLWC4, MLWC5,

		// Config codes
		CNDBC1, CNDBC2, CNDBC3,

		// Repository codes
		RCHK1,
		RURP1, RUCR1, RUUP1, RUDL1, RULS1, RUCT1,

		// Usecase codes
		UUGU1, UUCR1, UUCR2, UUUP1, UUUP2, UUDL1, UULS1, UUCT1,

		// Controller codes - User Public
		UCPCU0, UCPCU1, UCPCU2, UCPCU3, UCPCU4, UCPCU5, UCPCU6,
		UCPGU0, UCPGU1, UCPGU2, UCPGU3,
	}

	maxLen := 0
	for _, code := range codes {
		if len(code.Code) > maxLen {
			maxLen = len(code.Code)
		}
	}
	return maxLen
}

func init() {
	maxCodeLength = calculateMaxCodeLength()
}

// System codes
var (
	SM1 = MCode{"SM1", "Server Main start"}
	SM2 = MCode{"SM2", "Server Main error"}
	SM3 = MCode{"SM3", "Server ready"}
)

// Middleware Logger With Config codes
var (
	MLWC1 = MCode{"MLWC1", "Request start"}
	MLWC2 = MCode{"MLWC2", "Request error"}
	MLWC3 = MCode{"MLWC3", "Request success"}
	MLWC4 = MCode{"MLWC4", "Request client error"}
	MLWC5 = MCode{"MLWC5", "Request server error"}
)

// Config codes
var (
	CNDBC1 = MCode{"C-NDBC-1", "Attempting database connection"}
	CNDBC2 = MCode{"C-NDBC-2", "Database connection established"}
	CNDBC3 = MCode{"C-NDBC-3", "Database connection failed"}
)

// Repository codes
var (
	RCHK1 = MCode{"R-CHK-1", "Repository health check"}
	RURP1 = MCode{"R-URP-1", "User repository operation"}
	RUCR1 = MCode{"R-UCR-1", "User create operation"}
	RUUP1 = MCode{"R-UUP-1", "User update operation"}
	RUDL1 = MCode{"R-UDL-1", "User delete operation"}
	RULS1 = MCode{"R-ULS-1", "User list operation"}
	RUCT1 = MCode{"R-UCT-1", "User count operation"}
)

// Usecase codes - User
var (
	UUGU1 = MCode{"U-UGU-1", "Usecase get users"}
	UUCR1 = MCode{"U-UCR-1", "Usecase create user start"}
	UUCR2 = MCode{"U-UCR-2", "Usecase create user success"}
	UUUP1 = MCode{"U-UUP-1", "Usecase update user start"}
	UUUP2 = MCode{"U-UUP-2", "Usecase update user success"}
	UUDL1 = MCode{"U-UDL-1", "Usecase delete user"}
	UULS1 = MCode{"U-ULS-1", "Usecase list users"}
	UUCT1 = MCode{"U-UCT-1", "Usecase count users"}
)

// Gin Log codes
var (
	GINLOG = MCode{"GINLOG", "Gin framework log"}
)

// Controller codes - User Public Create User
var (
	UCPCU0 = MCode{"UCPCU0", "Request received"}
	UCPCU1 = MCode{"UCPCU1", "Bind request failed"}
	UCPCU2 = MCode{"UCPCU2", "Required fields missing"}
	UCPCU3 = MCode{"UCPCU3", "Email already exists"}
	UCPCU4 = MCode{"UCPCU4", "Password hash failed"}
	UCPCU5 = MCode{"UCPCU5", "User created"}
	UCPCU6 = MCode{"UCPCU6", "Response sent"}
)

// Controller codes - User Public Get Users
var (
	UCPGU0 = MCode{"UCPGU0", "Request received"}
	UCPGU1 = MCode{"UCPGU1", "Bind request failed"}
	UCPGU2 = MCode{"UCPGU2", "Users retrieved"}
	UCPGU3 = MCode{"UCPGU3", "Response sent"}
)
