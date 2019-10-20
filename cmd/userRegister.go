/*
Copyright © 2019 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"github.com/DanielXuuuuu/goAgenda/entity"
	"github.com/DanielXuuuuu/goAgenda/logger"
	"github.com/spf13/cobra"
	"errors"
	"regexp"
)

const userDataFile = "./data/userList.json"

// userRegisterCmd represents the userRegister command
var userRegisterCmd = &cobra.Command{
	Use:   "userRegister",
	Short: "user register",
	Long: "userRegister:\n  users are registered to the system by enter their name, password, email and phoneNumber ",
	Run: func(cmd *cobra.Command, args []string) {
		logger.WriteLog("[INFO] ", "userRegister called")
		users, err := entity.ReadFromFile(userDataFile)
		if err != nil {
			fmt.Println(err)
			return
		}
		username, _ := cmd.Flags().GetString("name")
		password, _:= cmd.Flags().GetString("password")
		email, _:= cmd.Flags().GetString("email")
		telephone, _ := cmd.Flags().GetString("telephone")
		
		if legal, err := registerCheck(users, username, password, email, telephone); !legal && err != nil {
			fmt.Println(err)
			logger.WriteLog("[ERROR] ", err.Error())
			logger.WriteLog("[INFO] ", "Register failed")
			return
		}
		
		newUser := entity.User{username, password, email, telephone}
		users = append(users, newUser)

		entity.WriteToFile(userDataFile, users)
		fmt.Println("New account register successfully!")
		logger.WriteLog("[INFO] ", "Register succeessfully")
	},
}

func registerCheck(users []entity.User, username string, password string, email string, telephone string) (bool, error) {
	if len(username) == 0{
		return false,errors.New("username missing")
	}else if len(password) == 0 {
		return false,errors.New("password missing")
	}else if len(email) == 0 {
		return false,errors.New("email missing")	
	}else if !validEmail(email){
		return false,errors.New("invalid email address")
	}else if len(telephone) == 0 {
		return false,errors.New("telephone missing")			
	}else if !validPhone(telephone){
		return false,errors.New("invalid phone number")
	}

	for _,user := range users {
		if user.Username == username {
			return false, errors.New("username existed")
		}else if user.Email == email {
			return false, errors.New("email registered")
		}else if user.Telephone == telephone {
			return false, errors.New("username registered")
		}
	}
	return true, nil
}

func validEmail(email string) (bool) {
	reg := regexp.MustCompile(`^\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$`)
    return reg.MatchString(email)
}

func validPhone(phone string) (bool) {
	reg := regexp.MustCompile("^(13[0-9]|14[579]|15[0-3,5-9]|16[6]|17[0135678]|18[0-9]|19[89])\\d{8}$")
    return reg.MatchString(phone)
}


func init() {
	rootCmd.AddCommand(userRegisterCmd)

	userRegisterCmd.Flags().StringP("name", "n", "", "user's name")
	userRegisterCmd.Flags().StringP("password", "p", "", "user's password")
	userRegisterCmd.Flags().StringP("email", "e", "", "user's email")
	userRegisterCmd.Flags().StringP("telephone", "t", "", "user's phone number")
	

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// userRegisterCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// userRegisterCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
