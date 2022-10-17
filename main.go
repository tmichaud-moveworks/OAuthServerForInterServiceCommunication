package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/google/uuid"

	"gopkg.in/oauth2.v3/errors"
	"gopkg.in/oauth2.v3/manage"
	"gopkg.in/oauth2.v3/models"
	"gopkg.in/oauth2.v3/server"
	"gopkg.in/oauth2.v3/store"
)

var domain = "http://localhost"
var port = ":8090"

//make sure we can crawl github/gitlab public repos to find leaked creds by having unique strings prepended to our id + secret
var moveworksClientIDIdentifier = "MCID_"
var moveworksClientSecretIdentifier = "MCS_"

//NOTE: JWTs are supported (See github link below in the comments for implementation details)

func main() {
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	/*
	   Both of these stores are memory only; we likely would want to write this data to a DB?
	   https://github.com/hebingchang/oauth2.v3/ has a list of DBs, which I've copied here with OOTB support:
	      BuntDB(default store)
	      Redis
	      MongoDB
	      MySQL
	      PostgreSQL
	      DynamoDB
	      XORM
	      GORM
	*/
	manager.MustTokenStorage(store.NewMemoryTokenStore())
	clientStore := store.NewClientStore()

	manager.MapClientStorage(clientStore)

	srv := server.NewDefaultServer(manager)
	srv.SetClientInfoHandler(server.ClientFormHandler)
	manager.SetRefreshTokenCfg(manage.DefaultRefreshTokenCfg)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("SetInternalErrorHandler Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("SetResponseErrorHandler Error:", re.Error.Error())
	})

	http.HandleFunc("/generateAccessToken", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()
		grant_type := r.FormValue("grant_type")
		/*
		   HUGE HACK ALERT
		      This *should* use something like the `oauth2.ClientCredentials` grant type instead, but as a POC I'm sticking to strings for now
		      As we allow for more types of OAuth2 flows, we can create a switch statement here to only allow the types we want
		      HOWEVER, it appears we can pretty much support all of these options out of the box if we want
		      For v1 it might not make sense, so I have limited this to just the client_credential grant type
		*/
		if grant_type == "client_credentials" {
			err := srv.HandleTokenRequest(w, r)
			if err != nil {
				fmt.Println(err.Error())
			} else {
				//This links out purely to make copy/pasting easier; remove for the actual implementation
				fmt.Fprintf(w, "\n\nMake sure to visit: "+domain+port+"/protectedEndpoint?access_token=<access_token>\n\n")
			}
		} else {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"Error": "We only support client_credential grants for now."})
		}
	})

	//in the real world, this should only be hittable by Control Center;
	//we should also make sure we give users the ability to hide and show the secret + ID in the UI
	http.HandleFunc("/getCredentials", func(w http.ResponseWriter, r *http.Request) {
		// Example: this will give us a 44 byte, base64 encoded output
		clientSecret, err := GenerateRandomEncodedBytes(32)
		if err != nil {
			// Serve an appropriately vague error to the
			// user, but log the details internally.
			panic(err)
		}
		clientId := base64.StdEncoding.EncodeToString([]byte(moveworksClientIDIdentifier + uuid.New().String()))

		err = clientStore.Set(clientId, &models.Client{
			ID:     clientId,
			Secret: clientSecret,
			Domain: domain + port,
		})

		if err != nil {
			fmt.Println(err.Error())
		}
		//to be removed in the real implementation; however giving end users the actual URL and how to structure it is likely a good idea
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<a target='_blank' href='"+domain+port+"/generateAccessToken?grant_type=client_credentials&client_secret="+clientSecret+"&client_id="+clientId+"'>ClickMe!</a>")
	})

	http.HandleFunc("/protectedEndpoint", validateToken(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("You can't see this without a valid auth token!"))
	}, srv))

	log.Fatal(http.ListenAndServe(port, nil))
}

func validateToken(f http.HandlerFunc, srv *server.Server) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := srv.ValidationBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		f.ServeHTTP(w, r)
	})
}

/*
Crypto stuffs for generating our client secrets
*/

func init() {
	assertAvailablePRNG()
}

func assertAvailablePRNG() {
	// Assert that a cryptographically secure PRNG is available.
	// Panic otherwise.
	buf := make([]byte, 1)

	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		panic(fmt.Sprintf("crypto/rand is unavailable: Read() failed with %#v", err))
	}
}

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

func GenerateRandomEncodedBytes(n int) (string, error) {
	b, err := GenerateRandomBytes(n)
	return moveworksClientSecretIdentifier + base64.StdEncoding.EncodeToString(b), err
}
