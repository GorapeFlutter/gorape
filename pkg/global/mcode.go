package global

import "strings"

// MCode represents a message code with predefined messages
// Naming convention: "{Scope}{PackageInitial}{CamelCaseFunction}{Number}"
// Scope: G=Global, S=Server, C=Client
// Example: GCLC1 = Global Config package, LoadConfig function, number 1
type MCode struct {
	Code    string
	Message string
}

// maxCodeLength is the maximum length of all mcode codes, calculated at initialization
var maxCodeLength int

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

// Mcode returns the provided MCode unchanged (for consistency with logging pattern)
func Mcode(mc MCode) MCode {
	return mc
}

// calculateMaxCodeLength calculates the maximum length from all defined mcodes
func calculateMaxCodeLength() int {
	maxLen := 0
	allMCodes := []MCode{
		// Global - Config package codes
		GCLC1, GCLC2, GCLC3, GCLC4,
		GCNBC1, GCNBC2,
		GCNBCWC1, GCNBCWC2, GCNBCWC3, GCNBCWC4, GCNBCWC5, GCNBCWC6,
		GCNBCFS1, GCNBCFS2, GCNBCFS3, GCNBCFS4, GCNBCFS5,
		GCCDB1, GCCDB2, GCCDB3, GCCDB4, GCCDB5,
		GCNDBC1, GCNDBC2, GCNDBC3,
		GCSLF1,
		GCNSMC1, GCNSMC2, GCNSMC3, GCNSMC4,
		GCGCE1, GCLCSM1, GCLCSM2, GCLCSM3, GCLCSM4, GCLCSM5,
		// Global - System codes
		GSYSE1, GSYSE2, GSYSE3,
		// Server package codes
		SSM1, SSM2, SSM3, SSM4, SSM5,
		SSIR1, SSIR2, SSIR3, SSIR4, SSIR5, SSIR6, SSIR7,
		// Server - Repository codes
		SRNRC1, SRNRC2, SRNRC3, SRNRC4, SRNRC5,
		SRNCR1, SRNCR2,
		SRNCH1, SRNCH2, SRNCH3, SRNCH4, SRNCH5, SRNCH6,
		SRNKC1, SRNKC2, SRNKC3,
		SRNUR1, SRNUR2,
		SRNUPR1, SRNUPR2, SRNUPR3, SRNUPR4, SRNUPR5, SRNUPR6,
		SRNGR1, SRNGR2, SRNGR3, SRNGR4, SRNGR5, SRNGR6, SRNGR7, SRNGR8, SRNGR9, SRNGR10,
		SRNDR1, SRNDR2, SRNDR3, SRNDR4, SRNDR5, SRNDR6, SRNDR7, SRNDR8, SRNDR9, SRNDR10, SRNDR11, SRNDR12, SRNDR13, SRNDR14, SRNDR15, SRNDR16, SRNDR17, SRNDR18, SRNDR19, SRNDR20, SRNDR21, SRNDR22, SRNDR23,
		SRNMR1, SRNMR2,
		SRNAT1, SRNAT2, SRNAT3, SRNAT4,
		SRNAS1, SRNAS2,
		SRNRR1, SRNRR2, SRNRR3, SRNRR4, SRNRR5, SRNRR6, SRNRR7, SRNRR8, SRNRR9, SRNRR10, SRNRR11, SRNRR12, SRNRR13, SRNRR14, SRNRR15, SRNRR16, SRNRR17, SRNRR18, SRNRR19, SRNRR20, SRNRR21, SRNRR22,
		SRNRSR1, SRNRSR2,
		SRNPR1, SRNPR2, SRNPR3, SRNPR4, SRNPR5, SRNPR6, SRNPR7, SRNPR8, SRNPR9, SRNPR10,
		SRNPG1, SRNPG2, SRNPG3,
		// Server - Middleware codes
		SMNL1, SMNL2, SMNL3, SMNL4, SMNL5,
		SMLWC1, SMLWC2, SMLWC3, SMLWC4, SMLWC5,
		SMFP1, SMFP2,
		SMFI1, SMFI2, SMFI3, SMFI4, SMFI5,
		SMFPR1, SMFPR2, SMFPR3, SMFPR4, SMFPR5,
		SMCA1, SMCA2, SMCA3, SMCA4, SMCA5, SMCA6,
		SMVJT1, SMVJT2, SMVJT3, SMVJT4, SMVJT5, SMVJT6,
		SMSUC1, SMSUC2,
		SMGUFC1, SMGUFC2, SMGUFC3,
		SMGUI1, SMGUI2, SMGUI3,
		SMGUU1, SMGUU2, SMGUU3,
		SMGUE1, SMGUE2, SMGUE3,
		SMGUN1, SMGUN2, SMGUN3,
		SMGUR1, SMGUR2, SMGUR3,
		SMGUC1, SMGUC2, SMGUC3,
		// Server - Controller codes
		SUCPCU0, SUCPCU1, SUCPCU2, SUCPCU3, SUCPCU4, SUCPCU5, SUCPCU6,
		SUCPGU0, SUCPGU1, SUCPGU2, SUCPGU3,
	}

	for _, mcode := range allMCodes {
		if len(mcode.Code) > maxLen {
			maxLen = len(mcode.Code)
		}
	}
	return maxLen
}

// init initializes the maxCodeLength by calculating from all mcodes
func init() {
	maxCodeLength = calculateMaxCodeLength()
}

// Message codes for gorape
var (
	// Global - Config package (GC prefix)
	// LoadConfig related
	GCLC1 = MCode{"GCLC1", "Configuration load start"}
	GCLC2 = MCode{"GCLC2", "Configuration load success"}
	GCLC3 = MCode{"GCLC3", "Configuration load failed"}
	GCLC4 = MCode{"GCLC4", "Configuration parse error"}

	// NewBaseConfig related
	GCNBC1 = MCode{"GCNBC1", "NewBaseConfig start"}
	GCNBC2 = MCode{"GCNBC2", "NewBaseConfig success"}

	// NewBaseConfigWithContext related
	GCNBCWC1 = MCode{"GCNBCWC1", "NewBaseConfigWithContext start"}
	GCNBCWC2 = MCode{"GCNBCWC2", "Using Secrets Manager"}
	GCNBCWC3 = MCode{"GCNBCWC3", "SECRET_ID not set, falling back to file"}
	GCNBCWC4 = MCode{"GCNBCWC4", "Secrets Manager load failed, falling back"}
	GCNBCWC5 = MCode{"GCNBCWC5", "Secrets Manager load success"}
	GCNBCWC6 = MCode{"GCNBCWC6", "File-based config success"}

	// NewBaseConfigFromSource related
	GCNBCFS1 = MCode{"GCNBCFS1", "NewBaseConfigFromSource start"}
	GCNBCFS2 = MCode{"GCNBCFS2", "Using secretsmanager source"}
	GCNBCFS3 = MCode{"GCNBCFS3", "Using localfile source"}
	GCNBCFS4 = MCode{"GCNBCFS4", "Using default source"}
	GCNBCFS5 = MCode{"GCNBCFS5", "Invalid CONFIG_SOURCE"}

	// ConnectDB related
	GCCDB1 = MCode{"GCCDB1", "ConnectDB start"}
	GCCDB2 = MCode{"GCCDB2", "Database already connected"}
	GCCDB3 = MCode{"GCCDB3", "Database connection attempt"}
	GCCDB4 = MCode{"GCCDB4", "Database connected successfully"}
	GCCDB5 = MCode{"GCCDB5", "Database connection failed"}

	// NewDBConnection related
	GCNDBC1 = MCode{"GCNDBC1", "NewDBConnection start"}
	GCNDBC2 = MCode{"GCNDBC2", "Database connection success"}
	GCNDBC3 = MCode{"GCNDBC3", "Database connection error"}

	// SetLoggerFactory related
	GCSLF1 = MCode{"GCSLF1", "Logger factory set"}

	// Secrets Manager related
	GCNSMC1 = MCode{"GCNSMC1", "NewSecretsManagerClient start"}
	GCNSMC2 = MCode{"GCNSMC2", "Using LocalStack"}
	GCNSMC3 = MCode{"GCNSMC3", "Using AWS production"}
	GCNSMC4 = MCode{"GCNSMC4", "Client created successfully"}
	GCGCE1  = MCode{"GCGCE1", "GetConfigFromEnv start"}
	GCLCSM1 = MCode{"GCLCSM1", "LoadConfigFromSecretsManager start"}
	GCLCSM2 = MCode{"GCLCSM2", "Secret retrieved successfully"}
	GCLCSM3 = MCode{"GCLCSM3", "Secret unmarshal success"}
	GCLCSM4 = MCode{"GCLCSM4", "Secret retrieval failed"}
	GCLCSM5 = MCode{"GCLCSM5", "Secret unmarshal failed"}

	// Global - System Error codes (GSYS prefix)
	GSYSE1 = MCode{"GSYSE1", "System error"}
	GSYSE2 = MCode{"GSYSE2", "Unexpected error"}
	GSYSE3 = MCode{"GSYSE3", "Fatal error"}

	// Server package (SS prefix)
	// Main function related
	SSM1 = MCode{"SSM1", "Server Main start"}
	SSM2 = MCode{"SSM2", "Server starting on port"}
	SSM3 = MCode{"SSM3", "Server ready"}
	SSM4 = MCode{"SSM4", "Server Run start"}
	SSM5 = MCode{"SSM5", "Server stopping"}

	// InitRouter related
	SSIR1 = MCode{"SSIR1", "InitRouter start"}
	SSIR2 = MCode{"SSIR2", "Redis client created"}
	SSIR3 = MCode{"SSIR3", "Redis client creation failed"}
	SSIR4 = MCode{"SSIR4", "Casbin enforcers initialized"}
	SSIR5 = MCode{"SSIR5", "Controllers initialized"}
	SSIR6 = MCode{"SSIR6", "Routes registered"}
	SSIR7 = MCode{"SSIR7", "Router initialization complete"}

	// Server - Repository (SR prefix)
	// NewRedisClient related
	SRNRC1 = MCode{"SRNRC1", "NewRedisClient start"}
	SRNRC2 = MCode{"SRNRC2", "Redis connection success"}
	SRNRC3 = MCode{"SRNRC3", "Redis connection failed"}
	SRNRC4 = MCode{"SRNRC4", "Redis ping success"}
	SRNRC5 = MCode{"SRNRC5", "Redis ping failed"}

	// NewCommonRepository related
	SRNCR1 = MCode{"SRNCR1", "NewCommonRepository start"}
	SRNCR2 = MCode{"SRNCR2", "CommonRepository created"}

	// KeycloakAdmin related
	SRNKC1 = MCode{"SRNKC1", "Keycloak Plan start"}
	SRNKC2 = MCode{"SRNKC2", "Keycloak Apply start"}
	SRNKC3 = MCode{"SRNKC3", "Keycloak apply start"}

	// ChallengeStore related
	SRNCH1 = MCode{"SRNCH1", "RedisChallenge CreateWithValue start"}
	SRNCH2 = MCode{"SRNCH2", "RedisChallenge Consume start"}
	SRNCH3 = MCode{"SRNCH3", "RedisChallenge Get start"}
	SRNCH4 = MCode{"SRNCH4", "MemoryChallenge CreateWithValue start"}
	SRNCH5 = MCode{"SRNCH5", "MemoryChallenge Consume start"}
	SRNCH6 = MCode{"SRNCH6", "MemoryChallenge Get start"}

	// NewUserRepository related
	SRNUR1 = MCode{"SRNUR1", "NewUserRepository start"}
	SRNUR2 = MCode{"SRNUR2", "UserRepository created"}

	// PrincipalRepository related
	SRNUPR1 = MCode{"SRNUPR1", "EnsurePrincipal start"}
	SRNUPR2 = MCode{"SRNUPR2", "EnsurePrincipal invalid identity"}
	SRNUPR3 = MCode{"SRNUPR3", "EnsurePrincipal create error"}
	SRNUPR4 = MCode{"SRNUPR4", "EnsurePrincipal load error"}
	SRNUPR5 = MCode{"SRNUPR5", "PrincipalBySubject start"}
	SRNUPR6 = MCode{"SRNUPR6", "PrincipalBySubject not found or error"}

	// NewGroupRepository related
	SRNGR1  = MCode{"SRNGR1", "NewGroupRepository start"}
	SRNGR2  = MCode{"SRNGR2", "GroupRepository created"}
	SRNGR3  = MCode{"SRNGR3", "Group start"}
	SRNGR4  = MCode{"SRNGR4", "Group not found or error"}
	SRNGR5  = MCode{"SRNGR5", "CreateGroup start"}
	SRNGR6  = MCode{"SRNGR6", "CreateGroup error"}
	SRNGR7  = MCode{"SRNGR7", "UpdateGroup start"}
	SRNGR8  = MCode{"SRNGR8", "UpdateGroup error"}
	SRNGR9  = MCode{"SRNGR9", "DeleteGroup start"}
	SRNGR10 = MCode{"SRNGR10", "DeleteGroup error"}

	// DeviceRepository related
	SRNDR1  = MCode{"SRNDR1", "Devices start"}
	SRNDR2  = MCode{"SRNDR2", "Devices done"}
	SRNDR3  = MCode{"SRNDR3", "Device start"}
	SRNDR4  = MCode{"SRNDR4", "Device not found or error"}
	SRNDR5  = MCode{"SRNDR5", "DeviceKey start"}
	SRNDR6  = MCode{"SRNDR6", "DeviceKey not found or error"}
	SRNDR7  = MCode{"SRNDR7", "UpdateCredentialData start"}
	SRNDR8  = MCode{"SRNDR8", "UpdateCredentialData error"}
	SRNDR9  = MCode{"SRNDR9", "UpdateCredentialData not found"}
	SRNDR10 = MCode{"SRNDR10", "RegisterDevice start"}
	SRNDR11 = MCode{"SRNDR11", "RegisterDevice error"}
	SRNDR12 = MCode{"SRNDR12", "RevokeDevice start"}
	SRNDR13 = MCode{"SRNDR13", "RevokeDevice error"}
	SRNDR14 = MCode{"SRNDR14", "MarkDeviceVerified start"}
	SRNDR15 = MCode{"SRNDR15", "MarkDeviceVerified error"}
	SRNDR16 = MCode{"SRNDR16", "GroupDevices start"}
	SRNDR17 = MCode{"SRNDR17", "GroupDevices done"}
	SRNDR18 = MCode{"SRNDR18", "BindDevice start"}
	SRNDR19 = MCode{"SRNDR19", "BindDevice error"}
	SRNDR20 = MCode{"SRNDR20", "UnbindDevice start"}
	SRNDR21 = MCode{"SRNDR21", "UnbindDevice error"}
	SRNDR22 = MCode{"SRNDR22", "DeviceGroupIDs start"}
	SRNDR23 = MCode{"SRNDR23", "DeviceGroupIDs done"}

	// NewMemberRepository related
	SRNMR1 = MCode{"SRNMR1", "NewMemberRepository start"}
	SRNMR2 = MCode{"SRNMR2", "MemberRepository created"}

	// AttestationVerifier related
	SRNAT1 = MCode{"SRNAT1", "VerifierRegistry Verify start"}
	SRNAT2 = MCode{"SRNAT2", "VerifierRegistry unsupported"}
	SRNAT3 = MCode{"SRNAT3", "VerifierRegistry verify error"}
	SRNAT4 = MCode{"SRNAT4", "AndroidVerifier Verify start"}

	// AttestationStore related
	SRNAS1 = MCode{"SRNAS1", "Attestations start"}
	SRNAS2 = MCode{"SRNAS2", "Attestations done"}

	// NewRoleRepository related
	SRNRR1  = MCode{"SRNRR1", "NewRoleRepository start"}
	SRNRR2  = MCode{"SRNRR2", "RoleRepository created"}
	SRNRR3  = MCode{"SRNRR3", "RoleDefinition start"}
	SRNRR4  = MCode{"SRNRR4", "RoleDefinition not found or error"}
	SRNRR5  = MCode{"SRNRR5", "RoleDefinitions start"}
	SRNRR6  = MCode{"SRNRR6", "RoleDefinitions done"}
	SRNRR7  = MCode{"SRNRR7", "PutRoleDefinition start"}
	SRNRR8  = MCode{"SRNRR8", "PutRoleDefinition error"}
	SRNRR9  = MCode{"SRNRR9", "DeleteRoleDefinition start"}
	SRNRR10 = MCode{"SRNRR10", "DeleteRoleDefinition error"}
	SRNRR11 = MCode{"SRNRR11", "RoleBindings start"}
	SRNRR12 = MCode{"SRNRR12", "RoleBindings done"}
	SRNRR13 = MCode{"SRNRR13", "ProjectRoleBindings start"}
	SRNRR14 = MCode{"SRNRR14", "ProjectRoleBindings done"}
	SRNRR15 = MCode{"SRNRR15", "GroupRoleBindings start"}
	SRNRR16 = MCode{"SRNRR16", "GroupRoleBindings done"}
	SRNRR17 = MCode{"SRNRR17", "RoleBinding start"}
	SRNRR18 = MCode{"SRNRR18", "RoleBinding not found or error"}
	SRNRR19 = MCode{"SRNRR19", "PutRoleBinding start"}
	SRNRR20 = MCode{"SRNRR20", "PutRoleBinding error"}
	SRNRR21 = MCode{"SRNRR21", "DeleteRoleBinding start"}
	SRNRR22 = MCode{"SRNRR22", "DeleteRoleBinding error"}

	// NewResourceRepository related
	SRNRSR1 = MCode{"SRNRSR1", "NewResourceRepository start"}
	SRNRSR2 = MCode{"SRNRSR2", "ResourceRepository created"}

	// ProjectRepository related
	SRNPR1  = MCode{"SRNPR1", "Project start"}
	SRNPR2  = MCode{"SRNPR2", "Project not found or error"}
	SRNPR3  = MCode{"SRNPR3", "ProjectByIssuer start"}
	SRNPR4  = MCode{"SRNPR4", "ProjectByIssuer not found or error"}
	SRNPR5  = MCode{"SRNPR5", "ProjectBySlug start"}
	SRNPR6  = MCode{"SRNPR6", "ProjectBySlug not found or error"}
	SRNPR7  = MCode{"SRNPR7", "PutProject start"}
	SRNPR8  = MCode{"SRNPR8", "PutProject error"}
	SRNPR9  = MCode{"SRNPR9", "Projects start"}
	SRNPR10 = MCode{"SRNPR10", "Projects done"}

	// ProvisioningRepository related
	SRNPG1 = MCode{"SRNPG1", "ApplyGorape start"}
	SRNPG2 = MCode{"SRNPG2", "ApplyGorape error"}
	SRNPG3 = MCode{"SRNPG3", "ApplyGorape done"}

	// Server - Middleware (SM prefix)
	// NewLogger related
	SMNL1 = MCode{"SMNL1", "NewLogger start"}
	SMNL2 = MCode{"SMNL2", "Log level set"}
	SMNL3 = MCode{"SMNL3", "Output destination set"}
	SMNL4 = MCode{"SMNL4", "Logger created"}
	SMNL5 = MCode{"SMNL5", "Failed to open log file"}

	// LoggerWithConfig (request logging)
	SMLWC1 = MCode{"SMLWC1", "Request start"}
	SMLWC2 = MCode{"SMLWC2", "Request processed"}
	SMLWC3 = MCode{"SMLWC3", "Request success"}
	SMLWC4 = MCode{"SMLWC4", "Client error"}
	SMLWC5 = MCode{"SMLWC5", "Server error"}

	// ForPublic middleware related
	SMFP1 = MCode{"SMFP1", "ForPublic middleware start"}
	SMFP2 = MCode{"SMFP2", "ForPublic middleware end"}

	// ForInternal middleware related
	SMFI1 = MCode{"SMFI1", "ForInternal middleware start"}
	SMFI2 = MCode{"SMFI2", "JWT validation start"}
	SMFI3 = MCode{"SMFI3", "JWT validation success"}
	SMFI4 = MCode{"SMFI4", "JWT validation failed"}
	SMFI5 = MCode{"SMFI5", "ForInternal middleware end"}

	// ForPrivate middleware related
	SMFPR1 = MCode{"SMFPR1", "ForPrivate middleware start"}
	SMFPR2 = MCode{"SMFPR2", "JWT validation start"}
	SMFPR3 = MCode{"SMFPR3", "JWT validation success"}
	SMFPR4 = MCode{"SMFPR4", "JWT validation failed"}
	SMFPR5 = MCode{"SMFPR5", "ForPrivate middleware end"}

	// CasbinAuthorization related
	SMCA1 = MCode{"SMCA1", "CasbinAuthorization start"}
	SMCA2 = MCode{"SMCA2", "User extracted from context"}
	SMCA3 = MCode{"SMCA3", "User not found in context"}
	SMCA4 = MCode{"SMCA4", "Authorization check start"}
	SMCA5 = MCode{"SMCA5", "Authorization granted"}
	SMCA6 = MCode{"SMCA6", "Authorization denied"}

	// validateJWTToken related
	SMVJT1 = MCode{"SMVJT1", "validateJWTToken start"}
	SMVJT2 = MCode{"SMVJT2", "Token extracted from header"}
	SMVJT3 = MCode{"SMVJT3", "Token missing"}
	SMVJT4 = MCode{"SMVJT4", "Token validation start"}
	SMVJT5 = MCode{"SMVJT5", "Token validation success"}
	SMVJT6 = MCode{"SMVJT6", "Token validation failed"}

	// setUserContext related
	SMSUC1 = MCode{"SMSUC1", "setUserContext start"}
	SMSUC2 = MCode{"SMSUC2", "User context set"}

	// getUserFromContext related
	SMGUFC1 = MCode{"SMGUFC1", "getUserFromContext start"}
	SMGUFC2 = MCode{"SMGUFC2", "User found in context"}
	SMGUFC3 = MCode{"SMGUFC3", "User not found in context"}

	// GetUserID related
	SMGUI1 = MCode{"SMGUI1", "GetUserID start"}
	SMGUI2 = MCode{"SMGUI2", "UserID retrieved"}
	SMGUI3 = MCode{"SMGUI3", "UserID not found"}

	// GetUserUUID related
	SMGUU1 = MCode{"SMGUU1", "GetUserUUID start"}
	SMGUU2 = MCode{"SMGUU2", "UserUUID retrieved"}
	SMGUU3 = MCode{"SMGUU3", "UserUUID not found"}

	// GetUserEmail related
	SMGUE1 = MCode{"SMGUE1", "GetUserEmail start"}
	SMGUE2 = MCode{"SMGUE2", "UserEmail retrieved"}
	SMGUE3 = MCode{"SMGUE3", "UserEmail not found"}

	// GetUserName related
	SMGUN1 = MCode{"SMGUN1", "GetUserName start"}
	SMGUN2 = MCode{"SMGUN2", "UserName retrieved"}
	SMGUN3 = MCode{"SMGUN3", "UserName not found"}

	// GetUserRole related
	SMGUR1 = MCode{"SMGUR1", "GetUserRole start"}
	SMGUR2 = MCode{"SMGUR2", "UserRole retrieved"}
	SMGUR3 = MCode{"SMGUR3", "UserRole not found"}

	// GetUserClaims related
	SMGUC1 = MCode{"SMGUC1", "GetUserClaims start"}
	SMGUC2 = MCode{"SMGUC2", "UserClaims retrieved"}
	SMGUC3 = MCode{"SMGUC3", "UserClaims not found"}

	// Server - Controller codes (SUC = Server User Controller, etc.)
	// User Controller Public (SUCPCU = Server User Controller Public Create User)
	SUCPCU0 = MCode{"SUCPCU0", "Request received"}
	SUCPCU1 = MCode{"SUCPCU1", "Bind request failed"}
	SUCPCU2 = MCode{"SUCPCU2", "Required fields missing"}
	SUCPCU3 = MCode{"SUCPCU3", "Email already exists"}
	SUCPCU4 = MCode{"SUCPCU4", "Password hash failed"}
	SUCPCU5 = MCode{"SUCPCU5", "User created"}
	SUCPCU6 = MCode{"SUCPCU6", "Response sent"}

	// User Controller Public Get Users
	SUCPGU0 = MCode{"SUCPGU0", "Request received"}
	SUCPGU1 = MCode{"SUCPGU1", "Bind request failed"}
	SUCPGU2 = MCode{"SUCPGU2", "Users retrieved"}
	SUCPGU3 = MCode{"SUCPGU3", "Response sent"}
)
