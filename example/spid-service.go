// Package main contains an example service provider implementation.
package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

var samlMiddleware *samlsp.Middleware

const tmplLayout = `<!DOCTYPE html>
<html lang="en-US">
<head>
    <title>spid-go Example Application</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
    <meta charset="UTF-8" />
</head>
<body>
    <div class="container">
        <h1>spid-go Example Application</h1>
        <div id="content">
        {{ . }}
        </div>
    </div>
</body>
</html>
`

const tmplUser = `<p>This page shows details about the currently logged user.</p>
<p><a class="btn btn-primary" href="/logout">Logout</a></p>
<h1>NameID:</h1>
<p>{{ .fiscalNumber}}</p>
<h2>SPID Level:</h2>
<p>{{ .Level }}</p>
<h2>Attributes</h2>
<table>
  <tr>
    <th>Key</th>
    <th>Value</th>
  </tr>
  {{ range $key, $val := . }}
      <tr>
        <td>{{ $key }}</td>
        <td>{{ $val }}</td>
	  </tr>
  {{ end }}
</table>
`

const tmplUser_2 = `<p>This page shows details about the currently logged user.</p>
<p><a class="btn btn-primary" href="/v2/logout">Logout</a></p>
<h1>NameID:</h1>
<p>{{ .fiscalNumber}}</p>
<h2>SPID Level:</h2>
<p>{{ .Level }}</p>
<h2>Attributes</h2>
<table>
  <tr>
    <th>Key</th>
    <th>Value</th>
  </tr>
  {{ range $key, $val := . }}
  <tr>
        <td>{{ $key }}</td>
        <td>{{ $val }}</td>
	  </tr>
  {{ end }}
</table>
`

func index(w http.ResponseWriter, r *http.Request) {
	session, _ := samlMiddleware.Session.GetSession(r)

	// lettura di variabile d'ambiente per il base path
	base_path := os.Getenv("BASE_PATH") // qualcosa tipo v2

	if base_path != "" {
		base_path = "/" + base_path
	}

	if session != nil {
		w.Header().Add("Location", base_path+"/hello")
		w.WriteHeader(http.StatusFound)
		return
	}
	t := template.Must(template.New("index").Parse(tmplLayout))
	button := samlMiddleware.ServiceProvider.GetButton(base_path + "/hello")
	t.Execute(w, template.HTML(button))
}

func hello(w http.ResponseWriter, r *http.Request) {
	t := template.Must(template.New("index").Parse(tmplLayout))

	var t2 bytes.Buffer
	session := samlsp.AttributesFromContext(r.Context())
	fmt.Println(session)

	// lettura di variabile d'ambiente per il base path
	base_path := os.Getenv("BASE_PATH") // qualcosa tipo v2
	tmpToUse := tmplUser

	if base_path != "" {
		tmpToUse = tmplUser_2
	}

	template.Must(template.New("user").Parse(tmpToUse)).Execute(&t2, session)

	t.Execute(w, template.HTML(t2.String()))
	//fmt.Fprintf(w, "Hello, %s!", samlsp.AttributeFromContext(r.Context(), "fiscalNumber"))
}

// Logout for SPID L1 only
func logout(w http.ResponseWriter, r *http.Request) {
	nameID := samlsp.AttributeFromContext(r.Context(), "urn:oasis:names:tc:SAML:attribute:subject-id")
	url, err := samlMiddleware.ServiceProvider.MakeRedirectLogoutRequest(nameID, "")
	//_, err := samlMiddleware.ServiceProvider.MakePostLogoutRequest(nameID, "")
	if err != nil {
		panic(err) // TODO handle error
	}

	err = samlMiddleware.Session.DeleteSession(w, r)
	if err != nil {
		panic(err) // TODO handle error
	}

	// lettura di variabile d'ambiente per il base path
	base_path := os.Getenv("BASE_PATH") // qualcosa tipo v2

	if base_path != "" {
		base_path = "/" + base_path
	}

	w.Header().Add("Location", url.String()+base_path)
	w.WriteHeader(http.StatusFound)
}

// Logout for SPID L2 and SPID L3

func logoutL2(w http.ResponseWriter, r *http.Request) {
	err := samlMiddleware.Session.DeleteSession(w, r)
	if err != nil {
		panic(err) // TODO handle error
	}

	// lettura di variabile d'ambiente per il base path
	base_path := os.Getenv("BASE_PATH") // qualcosa tipo v2

	base_path = "/" + base_path

	w.Header().Add("Location", base_path)
	w.WriteHeader(http.StatusFound)
}

func main() {
	keyPair, err := tls.LoadX509KeyPair("crt.pem", "key.pem")
	if err != nil {
		panic(err) // TODO handle error
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err) // TODO handle error
	}

	// Read IDP Metadata from URL
	/*xidpMetadataURL, err := url.Parse("https://demo.spid.gov.it/metadata.xml")
	if err != nil {
		panic(err) // TODO handle error
	}

	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient,
		*idpMetadataURL)
	if err != nil {
		panic(err) // TODO handle error
	}*/

	// Read IDP Metadata from file
	//data, err := os.ReadFile("agid-idp.xml")
	data, err := os.ReadFile("idp.xml")

	if err != nil {
		panic(err) // TODO handle error
	}
	idpMetadata, err := samlsp.ParseMetadata(data)
	if err != nil {
		panic(err) // TODO handle error
	}

	// lettura di variabile d'ambiente per il base path
	base_path := os.Getenv("BASE_PATH") // qualcosa tipo v2

	if base_path != "" {
		base_path = "/" + base_path
	}

	//rootURL, err := url.Parse("https://dev.oneidentity.pagopa.it" + base_path + "/")
	rootURL, err := url.Parse("http://localhost:8080" + base_path + "/")
	if err != nil {
		panic(err) // TODO handle error
	}

	samlMiddleware, _ = samlsp.New(samlsp.Options{
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
		SignRequest: true, // some IdP require the SLO request to be signed
		RequestedAuthnContext: &saml.RequestedAuthnContext{
			Comparison:           "minimum",
			AuthnContextClassRef: "https://www.spid.gov.it/SpidL2",
		},
		ForceAuthn: true,
	})
	app := http.HandlerFunc(hello)
	slo := http.HandlerFunc(logoutL2)
	home := http.HandlerFunc(index)

	http.Handle(base_path+"/", home)                                    // /v2
	http.Handle(base_path+"/hello", samlMiddleware.RequireAccount(app)) // /v2/hello
	http.Handle(base_path+"/saml/", samlMiddleware)                     // /v2/saml/
	http.Handle(base_path+"/logout", slo)                               // /v2/logout

	server := &http.Server{
		Addr:              ":8080",
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}
