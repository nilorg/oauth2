package oauth2

type CheckClientBasicFunc func(basic *ClientBasic) (err error)