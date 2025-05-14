package main

type PlaneRegistration struct {
	Tail      string `json:"tail"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

type Config struct {
	AuthUser            string              `json:"auth_user"`
	AuthPass            string              `json:"auth_pass"`
	SecretKey           string              `json:"secret_key"`
	DBFile              string              `json:"db_file"`
	PreRegisteredPlanes []PlaneRegistration `json:"pre_registered_planes"`
}
