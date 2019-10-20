package entity

import (
	"io/ioutil"
	"encoding/json"
	"os"
)

type User struct{
	Username string
	Password string
	Email string
	Telephone string
}

func ReadFromFile(filePath string) ([]User, error){
	var users []User
	str, err := ioutil.ReadFile(filePath)
	if err != nil {
		return users, err
	}
	jsonStr := string(str)

	json.Unmarshal([]byte(jsonStr), &users)
	return users, err
}

func WriteToFile(filePath string, users []User) error{
	if data, err := json.Marshal(users); err == nil{
		return ioutil.WriteFile(filePath, []byte(data), os.ModeAppend)
	}else{
		return err
	}
}