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
)

// userLogoutCmd represents the userLogout command
var userLogoutCmd = &cobra.Command{
	Use:   "userLogout",
	Short: "user logout",
	Long: "userLogout:\n  logined user logout",
	Run: func(cmd *cobra.Command, args []string) {
		logger.WriteLog("[INFO] ", "userLogout callled")
		if curUser, err := entity.ReadFromFile(curUserFile); err != nil {
			fmt.Println(err)
		}else if len(curUser) == 0{
			fmt.Println("please login first")
			logger.WriteLog("[ERROR] ", "Logout before login")
			logger.WriteLog("[INFO] ", "Logout failed")
		}else {
			fmt.Println("Logout successfully. Bye! " + curUser[0].Username + ".")
			logger.WriteLog("[INFO] ", "Logout successfully")
			var empty []entity.User
			entity.WriteToFile(curUserFile, empty)
		}
	},
}

func init() {
	rootCmd.AddCommand(userLogoutCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// userLogoutCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// userLogoutCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
