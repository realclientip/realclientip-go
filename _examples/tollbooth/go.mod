module github.com/realclientip/realclientip-go/_examples/tollbooth

go 1.18

replace github.com/realclientip/realclientip-go => ../..

require (
	github.com/didip/tollbooth/v6 v6.1.2
	github.com/realclientip/realclientip-go v0.0.0-20220324120256-a2b8bb8de17c
)

require (
	github.com/go-pkgz/expirable-cache v0.0.3 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/time v0.0.0-20200416051211-89c76fbcd5d1 // indirect
)
