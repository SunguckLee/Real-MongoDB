// Package kerberos implements authentication to MongoDB using kerberos
package kerberos

// #cgo windows CFLAGS: -Ic:/sasl/include
// #cgo windows LDFLAGS: -Lc:/sasl/lib

import (
	"github.com/mongodb/mongo-tools/common/options"
	"gopkg.in/mgo.v2"
)

const authMechanism = "GSSAPI"

func AddKerberosOpts(opts options.ToolOptions, dialInfo *mgo.DialInfo) {
	if dialInfo == nil {
		return
	}
	if opts.Kerberos == nil {
		return
	}
	if opts.Auth == nil || (opts.Auth.Mechanism != authMechanism &&
		dialInfo.Mechanism != authMechanism) {
		return
	}
	dialInfo.Service = opts.Kerberos.Service
	dialInfo.ServiceHost = opts.Kerberos.ServiceHost
	dialInfo.Mechanism = authMechanism
}
