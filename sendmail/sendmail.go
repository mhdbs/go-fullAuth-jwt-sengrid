package sendmail

import (
	"fmt"
	"os"

	logging "github.com/op/go-logging"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"github.com/spf13/viper"
)

var (
	configSendGrid        string
	configSendGridAddress string
)
var log = logging.MustGetLogger("iotmeta")
var format = logging.MustStringFormatter(
	`%{color}%{shortfunc} ▶ %{level:.4s} %{color:reset} %{message}`,
)

func init() {
	initiateLogger()

	configSendGrid = viper.GetString("SendGrid.SENDGRID_API_KEY")
	configSendGridAddress = viper.GetString("SendGrid.Address")
}

func initiateLogger() {
	viper.SetConfigName("global")
	viper.AddConfigPath("../go-fullAuth-jwt-sengrid")
	f, _ := os.OpenFile("access.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	configError := viper.ReadInConfig()
	backend := logging.NewLogBackend(f, "", 0)
	backendFormatter := logging.NewBackendFormatter(backend, format)
	backendLeveled := logging.AddModuleLevel(backend)
	fmt.Println("Log level : ", logging.GetLevel("iotserver"))
	logging.SetBackend(backendLeveled, backendFormatter)
	if configError != nil {
		log.Errorf("Fatal error config file: %s \n", configError)
		panic("Fatal error")
	}
}

func SendMail(username string, tokenString string, email string) string {

	from := mail.NewEmail("noreply@bilal", configSendGridAddress)
	subject := ("Click the link to authenticate user ")
	to := mail.NewEmail("", email)
	plainTextContent := "hello"
	htmlContent := "http://localhost:9000/routes/" + tokenString + "/" + email
	message := mail.NewSingleEmail(from, subject, to, plainTextContent, htmlContent)
	client := sendgrid.NewSendClient(configSendGrid)
	response, err := client.Send(message)
	fmt.Println(response)
	if err != nil {
		fmt.Println("err")
	}
	fmt.Println("ok")
	return tokenString

}
