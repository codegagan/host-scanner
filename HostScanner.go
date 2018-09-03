package main

import (
    "bufio"
    "fmt"
   "github.com/anvie/port-scanner"
    "os"
    "time"
    "encoding/json"
    "log"
    "net/http"
    "github.com/gorilla/mux"
    "strings"
    "github.com/gorilla/handlers"
)

const filename = "sys.list"

type status struct{
    host string
    stat []string
}

func check(e error) {
    if e != nil {
        panic(e)
    }
}

func checkPorts(host string, done chan string){
    ps := portscanner.NewPortScanner(host, 1* time.Second, 5)
    
    const serviceCount = 4
    
    serviceChannel:= make(chan string, serviceCount)

    go checkSsh(ps, serviceChannel)
    go checkHttp(ps, serviceChannel)
    go checkHttps(ps, serviceChannel)
    go checkSms(ps, serviceChannel)

    services:= make([]string, 0)
    
    for i:=0; i <serviceCount; i++ {
        if value := <- serviceChannel; len(value) >0 {
            services = append(services, value)
        }
    }

    
    done <- host+"="+strings.Join(services, "#")

}
 
func checkSsh(ps *portscanner.PortScanner, serviceChannel chan string) {
    if(ps.IsOpen(22)){
        serviceChannel <- "ssh"
    } else {
        serviceChannel <- ""
    }
    
}

func checkHttp(ps *portscanner.PortScanner, serviceChannel chan string) {
    if(ps.IsOpen(80)){
        serviceChannel <- "http"
    }else{
        serviceChannel <- ""
    }
}

func checkHttps(ps *portscanner.PortScanner, serviceChannel chan string) {
    if(ps.IsOpen(443)){
        serviceChannel <- "https"
    } else{
        serviceChannel <- ""
    }
}

func checkSms(ps *portscanner.PortScanner, serviceChannel chan string) {
    if(ps.IsOpen(3009)){
        serviceChannel <- "sms"
    } else {
        serviceChannel <- ""
    }
}

func getDdrStatus(filename string) map[string][]string{
    f, err := os.Open(filename)
	check(err)
    defer f.Close()

    status := make(map[string][]string)
    
    scanner := bufio.NewScanner(f)
    i := 0

    doneChannel := make(chan string, 100)

    for scanner.Scan() {
        host:= scanner.Text()
        i++
        go checkPorts(host, doneChannel)
    }

    check(scanner.Err())

    for j:=0;j<i;j++ {
      s:=  <- doneChannel
      key, value := convertStringToKeyValue(s)
      status[key] = value
    }
    return status
}

func convertStringToKeyValue(input string) (key string, value []string) {
    splitted := strings.Split(input, "=")
    key = splitted[0]
    value = strings.Split(splitted[1], "#")
    return key, value
} 

func getAll(w http.ResponseWriter, r *http.Request) {
    fmt.Println(r.RequestURI)
    json.NewEncoder(w).Encode(getDdrStatus(filename))
}

func getStatus(w http.ResponseWriter, r *http.Request) {
    params := mux.Vars(r)
    host := params["host"]
    fmt.Println(host)
    doneChannel := make(chan string, 10)
    go checkPorts(host, doneChannel)
    key, value := convertStringToKeyValue(<- doneChannel)
    mapValue := make(map[string][]string)
    mapValue[key] = value
    json.NewEncoder(w).Encode(mapValue)
}

func main(){

    allowedHeaders := handlers.AllowedHeaders([]string{"X-Requested-With"})
    allowedOrigins := handlers.AllowedOrigins([]string{"*"})
    allowedMethods := handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"})

    router := mux.NewRouter()
    router.HandleFunc("/status", getAll).Methods("GET")
    router.HandleFunc("/status/{host}", getStatus).Methods("GET")
    log.Fatal(http.ListenAndServe(":8000", handlers.CORS(allowedHeaders, allowedOrigins, allowedMethods)( router)))
}
