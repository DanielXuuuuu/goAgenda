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
)

const curUserFile = "./data/curUser.json"
var curUser []entity.User

// userLoginCmd represents the userLogin command
var userLoginCmd = &cobra.Command{
	Use:   "userLogin",
	Short: "user login",
	Long: "userLogin:\n  registered user login with username and password",
	Run: func(cmd *cobra.Command, args []string) {
		logger.WriteLog("[INFO] ", "userLogin called")
		users, err := entity.ReadFromFile(userDataFile)
		if err != nil {
			fmt.Println(err)
			return
		}
		username, _ := cmd.Flags().GetString("name")
		password, _:= cmd.Flags().GetString("password")

		if flag, err := loginCheck(users, username, password); flag == true{
			fmt.Println("Login successfully, welcome! " + username + ".")
			logger.WriteLog("[INFO] ", "Login successfully")
		}else{
			fmt.Println(err);
			logger.WriteLog("[ERROR] ", err.Error())
			logger.WriteLog("[INFO] ", "Login failed")
		}
	},
}

func loginCheck(users []entity.User, username string, password string)(bool, error){
	if curUser, err := entity.ReadFromFile(curUserFile); err != nil {
		return false, err
	}else if len(curUser) != 0{
		return false, errors.New("already login") 
	}

	if len(username) == 0 {
		return false, errors.New("missing username")
	}else if len(password) == 0 {
		return false, errors.New("missing password")
	}

	for _,user := range users {
		if user.Username == username && user.Password == password {
			curUser = append(curUser, user)
			entity.WriteToFile(curUserFile, curUser)
			return true, nil
		}
	}
	return false, errors.New("incorrect username or password, please check and try again!")
}

func init() {
	rootCmd.AddCommand(userLoginCmd)

	userLoginCmd.Flags().StringP("name", "n", "", "user's name")
	userLoginCmd.Flags().StringP("password", "p", "", "user's password")
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// userLoginCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// userLoginCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
