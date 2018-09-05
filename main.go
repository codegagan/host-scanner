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
    "github.com/sendgrid/rest"
    "crypto/tls"
)

const filename = "ddr.list"

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
    
    const serviceCount = 5
    
    serviceChannel:= make(chan string, serviceCount)

    go checkSsh(ps, serviceChannel)
    go checkHttp(ps, serviceChannel)
    go checkHttps(ps, serviceChannel)
    go checkSms(ps, serviceChannel)
    go checkVersion(host, serviceChannel)

    services:= make([]string, 0)
    
    for i:=0; i <serviceCount; i++ {
        if value := <- serviceChannel; len(value) >0 {
            services = append(services, value)
        }
    }

    
    done <- host+"="+strings.Join(services, "#")

}

func getSystemDetails(host string) SystemDetails{
    token:= getToken(host)
    details:= &SystemDetails{}
    if len(token) >0 {
        timeout := time.Duration(3 * time.Second)
        rest.DefaultClient.HTTPClient.Timeout = timeout
        Headers := make(map[string]string)
	    Headers["Content-Type"] = "application/json"
	    Headers["Accept"] = "application/json"
        Headers["X-DD-AUTH-TOKEN"] = token
        method := rest.Get
        baseURL := "https://" + host+":3009/rest/v1.0/system"
        request := rest.Request{
            Method:  method,
            BaseURL: baseURL,
            Headers: Headers,
        }

        response, err := rest.Send(request)

        if err != nil {
            fmt.Println(err)
        } else {
            err:= json.Unmarshal([]byte(response.Body), details)
            if err!= nil {
                fmt.Println(err)
            }
        }
    } 
    return *details
}

func getToken(host string) string {
    baseURL := "https://" + host+":3009/rest/v1.0/auth"
	Headers := make(map[string]string)
	Headers["Content-Type"] = "application/json"
	Headers["Accept"] = "application/json"
	var Body = []byte(`{ "auth_info":{ "username":"sysadmin","password":"abc123" } }`)
    queryParams := make(map[string]string)
    
    http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	method := rest.Post
	request := rest.Request{
		Method:      method,
		BaseURL:     baseURL,
		Headers:     Headers,
		QueryParams: queryParams,
		Body:        Body,
    }

    timeout := time.Duration(3 * time.Second)

    rest.DefaultClient.HTTPClient.Timeout = timeout

	response, err := rest.Send(request)
	if err != nil {
        fmt.Println(err)
        return ""
	} else {
        return response.Headers["X-Dd-Auth-Token"][0]
    }
}

func checkVersion(host string, serviceChannel chan string){

    details := getSystemDetails(host)

    if len(details.Version) >0 {
        serviceChannel <- details.Version
    }else{
        serviceChannel <- ""
    }

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

func getSystem(w http.ResponseWriter, r *http.Request) {
    params := mux.Vars(r)
    host := params["host"]
    fmt.Println(host)
    details:= getSystemDetails(host)
    json.NewEncoder(w).Encode(details)
}

type SystemDetails struct {
	Name             string `json:"name"`
	Type             string `json:"type"`
	Version          string `json:"version"`
	Serialno         string `json:"serialno"`
	Model            string `json:"model"`
	Uptime           string `json:"uptime"`
	UptimeSecs       int    `json:"uptime_secs"`
	MemSize          int64  `json:"mem_size"`
	TimeZone         string `json:"time_zone"`
	PhysicalCapacity struct {
		Total     int64 `json:"total"`
		Used      int   `json:"used"`
		Available int64 `json:"available"`
	} `json:"physical_capacity"`
	LogicalCapacity struct {
		Total     int64 `json:"total"`
		Used      int   `json:"used"`
		Available int64 `json:"available"`
	} `json:"logical_capacity"`
	CompressionFactor    float64 `json:"compression_factor"`
	CapacityUsageDetails []struct {
		Tier             string `json:"tier"`
		PhysicalCapacity struct {
			Total     int64 `json:"total"`
			Used      int   `json:"used"`
			Available int64 `json:"available"`
		} `json:"physical_capacity"`
		LogicalCapacity struct {
			Total     int64 `json:"total"`
			Used      int   `json:"used"`
			Available int64 `json:"available"`
		} `json:"logical_capacity"`
		CompressionFactor float64 `json:"compression_factor"`
	} `json:"capacity_usage_details"`
	License []struct {
		Feature string `json:"feature"`
	} `json:"license"`
	UUID string `json:"uuid"`
	Link []struct {
		Rel  string `json:"rel"`
		Href string `json:"href"`
	} `json:"link"`
}

func main(){

    allowedHeaders := handlers.AllowedHeaders([]string{"X-Requested-With"})
    allowedOrigins := handlers.AllowedOrigins([]string{"*"})
    allowedMethods := handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"})

    router := mux.NewRouter()
    router.HandleFunc("/api/status", getAll).Methods("GET")
    router.HandleFunc("/api/status/{host}", getStatus).Methods("GET")
    router.HandleFunc("/api/system/{host}", getSystem).Methods("GET")
    router.PathPrefix("/").Handler(http.FileServer(http.Dir("./ui/ddr-status/build/")))
    log.Fatal(http.ListenAndServe(":8000", handlers.CORS(allowedHeaders, allowedOrigins, allowedMethods)( router)))
}
