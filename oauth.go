package falconClientGolang

import (
	"context"
	"fmt"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
)

type falconClientGolang struct {
	falconClientId         string
	falconClientSecret     string
	falconUrlAccessToken   string
	falconUrlResourceOwner string
	falconAccountsUrl      string
}

func New(falconClientId, falconClientSecret, falconUrlAccessToken, falconUrlResourceOwner, falconAccountsUrl string) (falconClientGolang, *oauth2.Config) {
	config := falconClientGolang{falconClientId, falconClientSecret, falconUrlAccessToken, falconUrlResourceOwner, falconAccountsUrl}

	var credentials = &oauth2.Config{
		RedirectURL:  "",
		ClientID:     falconClientId,
		ClientSecret: falconClientSecret,
		Scopes:       []string{"email", "image_url", "organization"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://provider.com/o/oauth2/auth",
			TokenURL: "http://falcon.sdslabs.local/access_token",
		},
	}

	return config, credentials
}

// func parseJSON(path string) (map[string]interface{}, error) {
// 	var config map[string]interface{}
// 	file, err := ioutil.ReadFile(path)
// 	if err != nil {
// 		return config, err
// 	}
// 	err = json.Unmarshal(file, &config)
// 	if err != nil {
// 		return config, err
// 	}
// 	return config, nil
// }

// var config, _ = parseJSON("config.json")

// var falconClientGolang.falconUrlResourceOwner string = config["falcon_url_resource_owner_details"].(string)
// var falconClientGolang.falconAccountsUrl string = config["falcon_falconClientGolang.falconAccountsUrl"].(string)
var COOKIE_NAME string = "sdslabs"

func makeRequest(url string, token *oauth2.Token) ([]byte, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error setting up a request: %s", err.Error())
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making a request: %s", err.Error())
	}

	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed read response: %s", err.Error())
	}
	return contents, nil
}

func GetUserById(id string, config falconClientGolang, credentials *oauth2.Config) ([]byte, error) {
	token, err := credentials.Exchange(context.Background(), id)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}

	user_data, err := makeRequest(config.falconUrlResourceOwner+`/`+id, token)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	return user_data, nil
}

func GetUserByUsername(username string, config falconClientGolang, credentials *oauth2.Config) ([]byte, error) {
	token, err := credentials.Exchange(context.Background(), username)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}

	user_data, err := makeRequest(config.falconUrlResourceOwner+`/username/`+username, token)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	return user_data, nil
}

func GetUserByEmail(email string, config falconClientGolang, credentials *oauth2.Config) ([]byte, error) {
	token, err := credentials.Exchange(context.Background(), email)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}

	user_data, err := makeRequest(config.falconUrlResourceOwner+`/email/`+email, token)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	return user_data, nil
}

func GetLoggedInUser(cookies map[string][]string, config falconClientGolang, credentials *oauth2.Config) ([]byte, error) {
	// hash := cookies[COOKIE_NAME]
	var hash string = ""
	if hash == "" {
		return nil, fmt.Errorf("cookie not found")
	}

	token, err := credentials.Exchange(context.Background(), hash)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}

	user_data, err := makeRequest(config.falconUrlResourceOwner+`/logged_in_user/`+hash, token)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	return user_data, nil
}

func Login(cookies map[string][]string, config falconClientGolang, credentials *oauth2.Config, w http.ResponseWriter, r *http.Request) ([]byte, error) {
	user_data, err := GetLoggedInUser(cookies, config, credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to login with given credentials: %s", err.Error())
	}

	if user_data == nil {
		http.Redirect(w, r, config.falconAccountsUrl+`/login?redirect=//`, http.StatusTemporaryRedirect)
	}
	return user_data, nil
}
