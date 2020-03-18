package util

// UserProfile represents a user profile in the database
type UserProfile struct {
	UserProfileID int64  `json:"userProfileID" db:"UserProfileID"`
	Sub           string `json:"sub" db:"Sub"`
	FamilyName    string `json:"familyName" db:"FamilyName"`
	GivenName     string `json:"givenName" db:"GivenName"`
	Locale        string `json:"locale" db:"Locale"`
	Name          string `json:"name" db:"Name"`
	NickName      string `json:"nickname" db:"NickName"`
	Picture       string `json:"picture" db:"Picture"`
}

// UserProfileActivity represents a userprofileAcivity record in the database
type UserProfileActivity struct {
	UserProfileID int64  `json:"userProfileID" db:"UserProfileID"`
	Description   string `json:"description" db:"Description"`
	DateCreated   string `json:"dateCreated" db:"DateCreated"`
}
