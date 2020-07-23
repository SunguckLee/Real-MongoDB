package db

import (
	"github.com/mongodb/mongo-tools/common/options"
	"github.com/mongodb/mongo-tools/common/testutil"
	. "github.com/smartystreets/goconvey/convey"
	"reflect"
	"testing"
)

func TestNewSessionProvider(t *testing.T) {

	testutil.VerifyTestType(t, "db")

	Convey("When initializing a session provider", t, func() {

		Convey("with the standard options, a provider with a standard"+
			" connector should be returned", func() {
			opts := options.ToolOptions{
				Connection: &options.Connection{
					Port: DefaultTestPort,
				},
				SSL:  &options.SSL{},
				Auth: &options.Auth{},
			}
			provider, err := NewSessionProvider(opts)
			So(err, ShouldBeNil)
			So(reflect.TypeOf(provider.connector), ShouldEqual,
				reflect.TypeOf(&VanillaDBConnector{}))

		})

		Convey("the main session should be successfully "+
			" initialized", func() {
			opts := options.ToolOptions{
				Connection: &options.Connection{
					Port: DefaultTestPort,
				},
				SSL:  &options.SSL{},
				Auth: &options.Auth{},
			}
			provider, err := NewSessionProvider(opts)
			So(err, ShouldBeNil)
			So(provider.mainSession, ShouldBeNil)
			session, err := provider.GetSession()
			So(err, ShouldBeNil)
			So(session, ShouldNotBeNil)
			session.Close()
			So(provider.mainSession, ShouldNotBeNil)
			err = provider.mainSession.Ping()
			So(err, ShouldBeNil)
			provider.Close()
			So(func() {
				provider.mainSession.Ping()
			}, ShouldPanic)

		})

	})

}

type listDatabasesCommand struct {
	Databases []map[string]interface{} `json:"databases"`
	Ok        bool                     `json:"ok"`
}

func (self *listDatabasesCommand) AsRunnable() interface{} {
	return "listDatabases"
}
