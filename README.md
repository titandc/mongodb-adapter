MongoDB Adapter [![Build Status](https://travis-ci.org/casbin/mongodb-adapter.svg?branch=master)](https://travis-ci.org/casbin/mongodb-adapter) [![Coverage Status](https://coveralls.io/repos/github/casbin/mongodb-adapter/badge.svg?branch=master)](https://coveralls.io/github/casbin/mongodb-adapter?branch=master) [![Godoc](https://godoc.org/github.com/casbin/mongodb-adapter?status.svg)](https://godoc.org/github.com/casbin/mongodb-adapter)
====

MongoDB Adapter is the [Mongo DB](https://www.mongodb.com) adapter for [Casbin](https://github.com/casbin/casbin). With this library, Casbin can load policy from MongoDB or save policy to it.

## Installation

    go get -u github.com/titandc/mongodb-adapter/v2

## Simple Example

```go
package main

import (
	"github.com/casbin/casbin/v2"
	"github.com/titandc/mongodb-adapter/v2"
)

func main() {
	// Initialize a MongoDB adapter and use it in a Casbin enforcer:
	// The adapter currently requires X509 client authentication to the cluster.
	caFilePath := "/path/to/ca.crt"
	certificateKeyFilePath := "/path/to/client-cert.pem"
	replicaSet := "rs0"
	databaseName := "db1"
	mongodbServers := [...]string{mongodb-0:27017, mongodb-1:27017, mongodb-2:27017}

	a := mongodbadapter.NewAdapter(caFilePath, certificateKeyFilePath, replicaSet, databaseName, mongodbServers)
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", a)
	if err != nil {
		panic(err)
	}

	// Load the policy from DB.
	e.LoadPolicy()
	
	// Check the permission.
	e.Enforce("alice", "data1", "read")
	
	// Modify the policy.
	// e.AddPolicy(...)
	// e.RemovePolicy(...)
	
	// Save the policy back to DB.
	e.SavePolicy()
}
```

## Filtered Policies

```go
import "go.mongodb.org/mongo-driver/bson"

// This adapter also implements the FilteredAdapter interface. This allows for
// efficent, scalable enforcement of very large policies:
filter := &bson.M{"v0": "alice"}
e.LoadFilteredPolicy(filter)

// The loaded policy is now a subset of the policy in storage, containing only
// the policy lines that match the provided filter. This filter should be a
// valid MongoDB selector using BSON. A filtered policy cannot be saved.
```

## Getting Help

- [Casbin](https://github.com/casbin/casbin)

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.
