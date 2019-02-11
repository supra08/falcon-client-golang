package main

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
)

func parseJSON(path string) (map[string]interface{}, error) {
	var config map[string]interface{}
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return config, err
	}
	err = json.Unmarshal(file, &config)
	if err != nil {
		return config, err
	}
	return config, nil
}

var config, _ = parseJSON("config.json")

var credentials = &oauth2.Config{
	RedirectURL:  "",
	ClientID:     config["falcon_client_id"].(string),
	ClientSecret: config["falcon_client_secret"].(string),
	Scopes:       []string{"email", "image_url", "organization"},
	Endpoint: oauth2.Endpoint{
		AuthURL:  "https://provider.com/o/oauth2/auth",
		TokenURL: "http://falcon.sdslabs.local/access_token",
	},
}

var resourceOwnerDetailsUrl string = config["falcon_url_resource_owner_details"].(string)
var accounts_url string = config["falcon_accounts_url"].(string)
var COOKIE_NAME string = "sdslabs"

func MakeRequest(url string, token *oauth2.Token) ([]byte, error) {
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

func GetUserById(id string) ([]byte, error) {
	token, err := credentials.Exchange(context.Background(), id)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}

	user_data, err := make_request(resourceOwnerDetailsUrl+`/`+id, token)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	return user_data, nil
}

func GetUserByUsername(username string) ([]byte, error) {
	token, err := credentials.Exchange(context.Background(), username)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}

	user_data, err := make_request(resourceOwnerDetailsUrl+`/username/`+username, token)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	return user_data, nil
}

func GetUserByEmail(email string) ([]byte, error) {
	token, err := credentials.Exchange(context.Background(), email)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}

	user_data, err := make_request(resourceOwnerDetailsUrl+`/email/`+email, token)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	return user_data, nil
}

func GetLoggedInUser(cookies map[string][]string) ([]byte, error) {
	// hash := cookies[COOKIE_NAME]
	var hash string = ""
	if hash == "" {
		return nil, fmt.Errorf("cookie not found")
	}

	token, err := credentials.Exchange(context.Background(), hash)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}

	user_data, err := make_request(resourceOwnerDetailsUrl+`/logged_in_user/`+hash, token)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}
	return user_data, nil
}

func Login(cookies map[string][]string, w http.ResponseWriter, r *http.Request) ([]byte, error) {
	user_data, err := get_logged_in_user(cookies)
	if err != nil {
		return nil, fmt.Errorf("failed to login with given credentials: %s", err.Error())
	}

	if user_data == nil {
		http.Redirect(w, r, accounts_url+`/login?redirect=//`, http.StatusTemporaryRedirect)
	}
	return user_data, nil
}