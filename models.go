package oauth2

type TokenResponseModel struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        uint   `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	ExampleParameter string `json:"example_parameter"`
	Scope            string `json:"scope"`
}

type ClientBasic struct {
	ID     string `json:"client_id"`
	Secret string `json:"client_secret"`
}
