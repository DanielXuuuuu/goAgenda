package logger

import (
	"fmt"
	"log"
	"os"
)

const logFile = "./data/agendaLog.log" 

func WriteLog(prefix string, content string){
	var logHelper *log.Logger
	file, err := os.OpenFile(logFile,  os.O_RDWR |  os.O_APPEND | os.O_CREATE, 0644)
	if err != nil{
		fmt.Print(err)
	}
	defer file.Close()
	logHelper = log.New(file, prefix, log.Ldate | log.Ltime)
	logHelper.Println(content)
}