// Copyright 2018 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mongodbadapter

import (
	"context"
	"fmt"
	"github.com/casbin/casbin/v2/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"log"
	"strings"
	"time"
)

// CasbinRule represents a rule in Casbin.
type CasbinRule struct {
	PType string
	V0    string
	V1    string
	V2    string
	V3    string
	V4    string
	V5    string
}

// adapter represents the MongoDB adapter for policy storage.
type Adapter struct {
	client   *mongo.Client
	ctx      context.Context
	servers  []string
	dbName   string
	collName string
	filtered bool
}

// NewAdapter is the constructor for Adapter. If database name is not provided
// in the Mongo URL, 'casbin' will be used as database name.
func NewAdapter(caFilePath,
	certificateKeyFilePath,
	replicaSet,
	database string,
	servers []string) (*Adapter, error) {
	a := &Adapter{
		servers:  servers,
		dbName:   database,
		collName: "casbin_rules",
		filtered: false,
	}

	if err := a.ConnectToDB(caFilePath, certificateKeyFilePath, replicaSet); err != nil {
		return nil, err
	}

	return a, nil
}

func (a *Adapter) ConnectToDB(caFilePath, certificateKeyFilePath, replicaSet string) error {
	var err error

	uri_servers := strings.Join(a.servers[:], ",")
	uri := "mongodb://%s/?tlsCAFile=%s&tlsCertificateKeyFile=%s"
	uri = fmt.Sprintf(uri, uri_servers, caFilePath, certificateKeyFilePath)
	credential := options.Credential{
		AuthMechanism: "MONGODB-X509",
		AuthSource:    "$external",
	}
	a.ctx, _ = context.WithTimeout(context.Background(), 10*time.Second)
	a.client, err = mongo.Connect(a.ctx, options.Client().ApplyURI(uri).SetAuth(credential).SetReplicaSet(replicaSet))
	if err != nil {
		return err
	}

	if err := a.client.Ping(a.ctx, readpref.Primary()); err != nil {
		return err
	}
	fmt.Println("Successfully connected to MongoDB")

	if err = a.CreateDBIndex(); err != nil {
		return err
	}
	return nil
}

func (a *Adapter) CreateDBIndex() error {

	collection := a.client.Database(a.dbName).Collection(a.collName)
	indexes := []string{"ptype", "v0", "v1", "v2", "v3", "v4", "v5"}
	for _, k := range indexes {
		modIndex := mongo.IndexModel{
			Keys: bson.M{
				k: 1, // index in ascending order
			}, Options: nil,
		}
		name, err := collection.Indexes().CreateOne(context.Background(), modIndex)
		if err != nil {
			return err
		}
		fmt.Println("Successfully create index", name)
	}

	/* only for debug
	cursor, err := collection.Indexes().List(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}
	var results []bson.M
	if err := cursor.All(context.Background(), &results); err != nil {
		log.Fatal(err)
	}
	fmt.Println(results)*/

	return nil
}

func (a *Adapter) close() {
	_ = a.client.Disconnect(a.ctx)
}

func (a *Adapter) dropTable() error {
	collection := a.client.Database(a.dbName).Collection(a.collName)
	if err := collection.Drop(a.ctx); err != nil {
		return err
	}
	return nil
}

func loadPolicyLine(line CasbinRule, model model.Model) {
	key := line.PType
	sec := key[:1]

	tokens := []string{}
	if line.V0 != "" {
		tokens = append(tokens, line.V0)
	} else {
		goto LineEnd
	}

	if line.V1 != "" {
		tokens = append(tokens, line.V1)
	} else {
		goto LineEnd
	}

	if line.V2 != "" {
		tokens = append(tokens, line.V2)
	} else {
		goto LineEnd
	}

	if line.V3 != "" {
		tokens = append(tokens, line.V3)
	} else {
		goto LineEnd
	}

	if line.V4 != "" {
		tokens = append(tokens, line.V4)
	} else {
		goto LineEnd
	}

	if line.V5 != "" {
		tokens = append(tokens, line.V5)
	} else {
		goto LineEnd
	}

LineEnd:
	model[sec][key].Policy = append(model[sec][key].Policy, tokens)
}

// LoadPolicy loads policy from database.
func (a *Adapter) LoadPolicy(model model.Model) error {
	return a.LoadFilteredPolicy(model, bson.D{})
}

// LoadFilteredPolicy loads matching policy lines from database. If not nil,
// the filter must be a valid MongoDB selector.
func (a *Adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	var err error

	if filter == nil {
		a.filtered = false
	} else {
		a.filtered = true
	}
	line := CasbinRule{}

	collection := a.client.Database(a.dbName).Collection(a.collName)
	cursor, err := collection.Find(context.Background(), filter)
	if err != nil {
		return err
	}
	defer cursor.Close(context.Background())

	for cursor.Next(a.ctx) {
		err := cursor.Decode(&line)
		if err != nil {
			log.Fatal(err)
			return err
		}
		loadPolicyLine(line, model)
	}
	return nil
}

// IsFiltered returns true if the loaded policy has been filtered.
func (a *Adapter) IsFiltered() bool {
	return a.filtered
}

func savePolicyLine(ptype string, rule []string) CasbinRule {
	line := CasbinRule{
		PType: ptype,
	}

	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}

	return line
}

// SavePolicy saves policy to database.
func (a *Adapter) SavePolicy(model model.Model) error {
	if a.filtered {
		return fmt.Errorf("cannot save a filtered policy")
	}
	if err := a.dropTable(); err != nil {
		return err
	}

	var lines []interface{}

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, &line)
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, &line)
		}
	}

	collection := a.client.Database(a.dbName).Collection(a.collName)
	res, err := collection.InsertMany(context.Background(), lines)
	if err != nil {
		return err
	}
	fmt.Printf("inserted documents with IDs %v\n", res.InsertedIDs)
	return nil
}

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)

	collection := a.client.Database(a.dbName).Collection(a.collName)
	res, err := collection.InsertOne(context.Background(), line)
	if err != nil {
		return err
	}
	fmt.Printf("inserted documents with IDs %d\n", res.InsertedID)
	return nil
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)

	collection := a.client.Database(a.dbName).Collection(a.collName)
	res, err := collection.DeleteOne(context.Background(), line, nil)
	if err != nil {
		return err
	}
	fmt.Printf("deleted %v documents\n", res.DeletedCount)
	return nil
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	selector := make(map[string]interface{})
	selector["ptype"] = ptype

	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		if fieldValues[0-fieldIndex] != "" {
			selector["v0"] = fieldValues[0-fieldIndex]
		}
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		if fieldValues[1-fieldIndex] != "" {
			selector["v1"] = fieldValues[1-fieldIndex]
		}
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		if fieldValues[2-fieldIndex] != "" {
			selector["v2"] = fieldValues[2-fieldIndex]
		}
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		if fieldValues[3-fieldIndex] != "" {
			selector["v3"] = fieldValues[3-fieldIndex]
		}
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		if fieldValues[4-fieldIndex] != "" {
			selector["v4"] = fieldValues[4-fieldIndex]
		}
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		if fieldValues[5-fieldIndex] != "" {
			selector["v5"] = fieldValues[5-fieldIndex]
		}
	}

	collection := a.client.Database(a.dbName).Collection(a.collName)
	res, err := collection.DeleteMany(context.Background(), selector, nil)
	if err != nil {
		return err
	}
	fmt.Printf("deleted %v documents\n", res.DeletedCount)
	return err
}
