package falconClientGolang

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

type DataResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type falconClientGolang struct {
	falconClientId         string
	falconClientSecret     string
	falconUrlAccessToken   string
	falconUrlResourceOwner string
	falconAccountsUrl      string
}

func New(falconClientId, falconClientSecret, falconUrlAccessToken, falconUrlResourceOwner, falconAccountsUrl string) falconClientGolang {
	config := falconClientGolang{falconClientId, falconClientSecret, falconUrlAccessToken, falconUrlResourceOwner, falconAccountsUrl}
	return config
}

var COOKIE_NAME string = "sdslabs"

func makeRequest(url, token string) (string, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("error setting up a request: %s", err.Error())
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	response, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making a request: %s", err.Error())
	}

	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("failed read response: %s", err.Error())
	}
	return string(contents), nil
}

func getToken(config falconClientGolang) string {
	payload := strings.NewReader("client_id=" + config.falconClientId + "&client_secret=" + config.falconClientSecret + "&grant_type=client_credentials")
	req, _ := http.NewRequest("POST", config.falconUrlAccessToken, payload)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)
	response := &DataResponse{}
	json.Unmarshal([]byte(string(body)), &response)

	return string(response.AccessToken)
}

func GetUserById(id string, config falconClientGolang) (string, error) {
	token := getToken(config)
	user_data, err := makeRequest(config.falconUrlResourceOwner+"id/"+id, token)
	if err != nil {
		return "", fmt.Errorf("failed getting user info: %s", err.Error())
	}
	return user_data, nil
}

func GetUserByUsername(username string, config falconClientGolang) (string, error) {
	token := getToken(config)
	user_data, err := makeRequest(config.falconUrlResourceOwner+"username/"+username, token)
	if err != nil {
		return "", fmt.Errorf("failed getting user info: %s", err.Error())
	}
	return user_data, nil
}

func GetUserByEmail(email string, config falconClientGolang) (string, error) {
	token := getToken(config)
	user_data, err := makeRequest(config.falconUrlResourceOwner+"email/"+email, token)
	if err != nil {
		return "", fmt.Errorf("failed getting user info: %s", err.Error())
	}
	return user_data, nil
}

func GetLoggedInUser(config falconClientGolang, hash string) (string, error) {
	// hash := cookies[COOKIE_NAME]
	// hash, _ := r.Cookie(COOKIE_NAME)
	// fmt.Fprint(w, cookie)
	fmt.Println(hash)
	// var hash string = strings.Split(cookie, "=")[1].(string)
	// fmt.Println(hash)
	if hash == "" {
		return "", fmt.Errorf("cookie not found")
	}
	token := getToken(config)
	user_data, err := makeRequest(config.falconUrlResourceOwner+`/users/logged_in_user/`+hash, token)
	if err != nil {
		return "", fmt.Errorf("failed getting user info: %s", err.Error())
	}
	return user_data, nil
}

func Login(config falconClientGolang, w http.ResponseWriter, r *http.Request) (string, error) {
	user_data, err := GetLoggedInUser(config, "")
	if err != nil {
		return "", fmt.Errorf("failed to login with given credentials: %s", err.Error())
	}

	if user_data == "" {
		http.Redirect(w, r, config.falconAccountsUrl+`/login?redirect=//`, http.StatusTemporaryRedirect)
	}
	return user_data, nil
}
