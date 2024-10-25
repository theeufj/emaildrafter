package middleware

// import (
// 	"encoding/json"
// 	"io"
// 	"log"
// 	"net/http"
// 	"os"

// 	"github.com/joho/godotenv"
// 	"golang.org/x/oauth2"
// 	"golang.org/x/oauth2/microsoft"
// )

// // generate a new results struct to handle the unmarshalling of the user obeject returned by Microsoft.
// type microsoftUser struct {
// 	DisplayName       string `json:"displayName"`
// 	GivenName         string `json:"givenName"`
// 	Surname           string `json:"surname"`
// 	UserPrincipalName string `json:"userPrincipalName"`
// 	Id                string `json:"id"`
// 	Mail              string `json:"mail"`
// 	MobilePhone       string `json:"mobilePhone"`
// 	JobTitle          string `json:"jobTitle"`
// 	OfficeLocation    string `json:"officeLocation"`
// }

// var ssoMicrofsoft *oauth2.Config

// // GraphHelper is a helper for the Microsoft Graph API
// // the following needs to interative micrsoft graph api
// func init() {
// 	err := godotenv.Load("./.env")
// 	if err != nil {
// 		log.Fatal("Error loading .env file")
// 	}
// 	ssoMicrofsoft = &oauth2.Config{
// 		RedirectURL:  os.Getenv("MicrosoftRedirectUrl"),
// 		ClientID:     os.Getenv("AppIDMicrosoft"),
// 		ClientSecret: os.Getenv("MicrosoftClientSecret"),
// 		Scopes:       []string{"user.read", "offline_access", "Mail.ReadWrite", "mail.send"},
// 		Endpoint:     microsoft.AzureADEndpoint(os.Getenv("MicrosoftTenantID")),
// 	}
// }

// func Signin_microsoft(w http.ResponseWriter, r *http.Request) {
// 	//log.Println(RandomString)
// 	url := ssoMicrofsoft.AuthCodeURL(RandomString, oauth2.ApprovalForce)
// 	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
// }

// func Callback_microsoft(w http.ResponseWriter, r *http.Request) {
// 	state := r.FormValue("state")
// 	code := r.FormValue("code")
// 	if state != RandomString {
// 		http.Error(w, "State invalid", http.StatusBadRequest)
// 		return
// 	}
// 	token, err := ssoMicrofsoft.Exchange(oauth2.NoContext, code)

// 	if err != nil && token == nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}
// 	//log.Println(state)
// 	result, err := getInfomation(token)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	//set cookie up
// 	vars := JWTValues{}
// 	vars.Set(result.Id, "Secured")
// 	vars.Set(result.Mail, "Email")
// 	toke := CreateJWTTokenForUser(vars)
// 	cookie := http.Cookie{
// 		Name:     "secureCookie",
// 		Value:    toke,
// 		Path:     "/",
// 		MaxAge:   3600,
// 		HttpOnly: true,
// 		Secure:   true,
// 		SameSite: http.SameSiteStrictMode,
// 	}

// 	cookie_email := http.Cookie{
// 		Name:     "user_email",
// 		Value:    result.Mail,
// 		Path:     "/",
// 		MaxAge:   360000000,
// 		HttpOnly: true,
// 		Secure:   true,
// 		SameSite: http.SameSiteStrictMode,
// 	}

// 	http.SetCookie(w, &cookie)
// 	http.SetCookie(w, &cookie_email)
// 	http.Redirect(w, r, "/", http.StatusFound)
// 	log.Println("Logging in...")
// 	http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
// }

// func getInfomation(t *oauth2.Token) (microsoftUser, error) {
// 	var result microsoftUser
// 	client := ssoMicrofsoft.Client(oauth2.NoContext, t)
// 	resp, err := client.Get("https://graph.microsoft.com/v1.0/me")
// 	if err != nil {
// 		log.Println("Error getting user information", err)
// 	}
// 	defer resp.Body.Close()
// 	data, err := io.ReadAll(resp.Body)
// 	err = json.Unmarshal(data, &result)

// 	return result, nil
// }
