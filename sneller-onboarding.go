/*
 * (C) 2022 Sneller, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	golog "log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/google/uuid"
)

type SnellerConfig struct {
	Database       string
	Table          string
	SourceBucket   string
	SourcePath     string
	SourceWildcard string
	SourceFormat   string
}

type NewTenantInfo struct {
	OrgName string
	Email   string
}

type TenantInfo struct {
	TenantID    string `json:"tenantID"`
	TokenID     string `json:"tokenID"`
	TokenSecret string `json:"tokenSecret"`
}

const (
	SnellerPermission = "sneller-permissions-"
	SnellerRole       = "sneller-role-"
)

var (
	Region              = "us-east-1"
	Uid                 = uuid.New().String()[:7]
	SnellerAwsAccountId = "701831592002"
	MasterToken         = ""
	iamClient           *iam.Client
	s3Client            *s3.Client
	log2json            = false
	firstJsonLine       = true
)

func main() {
	if len(os.Args) > 1 {
		log2json = strings.ToLower(os.Args[1]) == "--json"
	}

	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(Region))
	if err != nil {
		golog.Panicf("Unable to load AWS credentials: %v", err)
	}
	iamClient = iam.NewFromConfig(cfg)
	s3Client = s3.NewFromConfig(cfg)

	err = performOnboarding(ctx)
	if err != nil {
		golog.Fatalf("Failed to perform onboarding: %v", err)
	}
}

func performOnboarding(ctx context.Context) (err error) {

	if log2json {
		fmt.Print("{") // print opening brace
		defer func() {
			fmt.Println("}") // print closing brace
		}()
	}

	// Get inputs
	config, newTenant, tenantPtr := readEnvironmentVars()

	var tenant TenantInfo
	if newTenant != nil {
		// Create tenant and access token for tenant
		if tenant, err = createTenant(newTenant); err != nil {
			return err
		}
	} else {
		tenant = *tenantPtr
	}

	// TODO: Check if we can skip setting up the Sneller bucket (invoke checkTenantForBucketConfig(tenant))

	snellerBucket := "sneller-" + strings.ToLower(tenant.TenantID) + "-" + Uid[:4]

	// Configure the policy and associated role for required S3 access to Sneller bucket
	roleName, err := setupSnellerBucket(ctx, snellerBucket, SnellerAwsAccountId, tenant)
	if err != nil {
		return
	}

	// Configure a data source
	if err = setupDataSource(ctx, roleName, tenant, config); err != nil {
		return
	}

	// Get sneller endpoint
	snellerEndpoint := getEndpoint()

	if !log2json {
		log("==================================", "")
	}
	log("sneller endpoint", snellerEndpoint)
	log("           token", tenant.TokenSecret)
	log("        database", config.Database)
	log("           table", config.Table)
	if !log2json {
		log("           query", fmt.Sprintf(`curl -s -G --data-urlencode "query=SELECT COUNT(*) FROM %s" \`, config.Table))
		fmt.Printf(`                    --data-urlencode "database=%s" --data-urlencode "json" \`+"\n", config.Database)
		fmt.Printf(`                    -H "Authorization: Bearer %s" '%s/executeQuery'`+"\n", tenant.TokenSecret, snellerEndpoint)
	}

	return nil
}

func log(s1, s2 string) {
	if log2json {
		if !firstJsonLine {
			fmt.Println(",")
		}
		firstJsonLine = false
		key := strings.TrimSpace(s1)
		key = strings.ToLower(strings.ReplaceAll(key, " ", "-"))
		val := strings.TrimSpace(s2)
		val = strings.ReplaceAll(val, `"`, `\"`)
		fmt.Printf(`"%s":"%s"`, key, val)
	} else {
		fmt.Printf("%s: %s\n", s1, s2)
	}
}

func readEnvironmentVars() (config SnellerConfig, newTenant *NewTenantInfo, tenant *TenantInfo) {

	snellerDatabase, ok1 := os.LookupEnv("SNELLER_DATABASE")
	snellerTable, ok2 := os.LookupEnv("SNELLER_TABLE")
	sourceBucket, ok3 := os.LookupEnv("SOURCE_BUCKET")
	sourcePath, ok4 := os.LookupEnv("SOURCE_PATH")
	sourceWildcard, ok5 := os.LookupEnv("SOURCE_WILDCARD")
	sourceFormat, ok6 := os.LookupEnv("SOURCE_FORMAT")
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
		golog.Fatalln("Missing environment variables")
	}
	sourceBucket = strings.TrimPrefix(sourceBucket, "s3://")
	if strings.HasSuffix(sourceBucket, "/") {
		golog.Fatalln("SOURCE_BUCKET should not end with trailing slash ('/')")
	}
	if strings.HasPrefix(sourcePath, "/") || strings.HasSuffix(sourcePath, "/") {
		golog.Fatalln("SOURCE_PATH should not start or end with slash ('/')")
	}
	if !(sourceFormat == "json" || sourceFormat == "json.gz" || sourceFormat == "json.zst" || sourceFormat == "cloudtrail.json.gz") {
		golog.Fatalln("Bad format for SOURCE_FORMAT")
	}

	config = SnellerConfig{
		Database:       snellerDatabase,
		Table:          snellerTable,
		SourceBucket:   sourceBucket,
		SourcePath:     sourcePath,
		SourceWildcard: sourceWildcard,
		SourceFormat:   sourceFormat,
	}

	if snellerAwsAccountId, other := os.LookupEnv("SNELLER_AWS_ACCOUNT_ID"); other {
		SnellerAwsAccountId = snellerAwsAccountId
	}
	tenantID, existing1 := os.LookupEnv("TENANT_ID")
	tenantSecret, existing2 := os.LookupEnv("TENANT_SECRET")
	if existing1 && existing2 {
		// TODO: Get tenant info including ?
		return config, nil, &TenantInfo{
			TenantID:    tenantID,
			TokenSecret: tenantSecret,
		}
	}
	tenantOrgName, new1 := os.LookupEnv("TENANT_ORG_NAME")
	tenantEmail, new2 := os.LookupEnv("TENANT_EMAIL")
	masterToken, new3 := os.LookupEnv("MASTER_TOKEN")
	if new1 && new2 && new3 {
		MasterToken = masterToken
		return config, &NewTenantInfo{
			OrgName: tenantOrgName,
			Email:   tenantEmail,
		}, nil
	} else {
		golog.Fatalln("Error while reading tenant environment variables")
	}
	return config, nil, nil
}

func invokeSnellerApi(method, api, token string, values url.Values, body io.Reader) (string, error) {

	// TODO: Set API endpoint for production
	snellerApiEndpoint := "https://latest-api-staging.us-east-1.sneller.io"

	if SnellerAwsAccountId != "701831592002" {
		snellerApiEndpoint = "https://" + "latest-api-master" + "." + Region + ".sneller-dev.io"
	}

	target, _ := url.Parse(snellerApiEndpoint + api)
	target.RawQuery = values.Encode()

	req, err := http.NewRequest(method, target.String(), body)
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Accept", "application/json")

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if !(resp.StatusCode >= 200 && resp.StatusCode < 300) {
		return "", errors.New(fmt.Sprintf("Sneller API error (%d): %s", resp.StatusCode, string(respBody)))
	}

	return string(respBody), nil
}

func createTenant(newTenant *NewTenantInfo) (tenant TenantInfo, err error) {

	// Create new tenant (including access token)
	values := url.Values{}
	values.Set("name", newTenant.OrgName)
	values.Set("email", newTenant.Email)
	values.Set("createToken", "1")
	target := "/tenant/me"
	if !(len(MasterToken) <= 40 && MasterToken[:2] == "SA") {
		// Make sure to change the endpoint to "/tenant" and use the
		// JWT from the global Cognito userpool, if you want to create
		// a global tenant (not available for customers).
		target = "/tenant"
	}
	var body string
	if body, err = invokeSnellerApi("POST", target, MasterToken, values, nil); err != nil {
		return
	} else if err = json.Unmarshal([]byte(body), &tenant); err != nil {
		return
	}

	// Activate tenant
	activate := url.Values{}
	activate.Set("operation", "activate")
	_, err = invokeSnellerApi("PATCH", "/tenant/"+tenant.TenantID, tenant.TokenSecret, activate, nil)
	if err != nil {
		return
	}
	log("Created new tenant                ", tenant.TenantID)
	return
}

func checkTenantForBucketConfig(tenant TenantInfo) {

	type MfaRequirement string

	type tenantRegionInfo struct {
		Bucket           string
		RegionRoleArn    string
		RegionExternalID string
	}

	type tenantInfo struct {
		TenantID      string
		TenantState   string
		TenantName    string
		HomeRegion    string
		Email         string
		TenantRoleArn string
		Mfa           MfaRequirement
		CreatedAt     time.Time
		ActivatedAt   *time.Time
		DeactivatedAt *time.Time
		Regions       map[string]tenantRegionInfo `json:",omitempty"`
	}

	values := url.Values{}
	values.Set("regions", "all")
	out, err := invokeSnellerApi("GET", "/tenant/"+tenant.TenantID, tenant.TokenSecret, values, nil)
	if err != nil {
		return
	}

	var ti tenantInfo
	err = json.Unmarshal([]byte(out), &ti)
	if tri, ok := ti.Regions[Region]; ok {
		log("tenantRegionInfo", fmt.Sprintf("%s", tri))
	}
	return
}

func makeSnellerBucket(ctx context.Context, snellerBucket, region string) (err error) {

	in := s3.CreateBucketInput{
		Bucket: aws.String(snellerBucket),
		ACL:    types.BucketCannedACLPrivate,
	}
	if region != "us-east-1" {
		in.CreateBucketConfiguration = &types.CreateBucketConfiguration{LocationConstraint: types.BucketLocationConstraint(region)}
	}

	if _, err = s3Client.CreateBucket(ctx, &in); err != nil {
		return
	}
	return
}

func setupSnellerBucket(ctx context.Context, snellerBucket, snellerAwsAccountId string, tenant TenantInfo) (roleName string, err error) {

	// Make Sneller bucket
	if err = makeSnellerBucket(ctx, snellerBucket, Region); err != nil {
		return
	}
	log("Created sneller bucket            ", snellerBucket)

	var roleArn string
	if roleArn, roleName, err = createSnellerRoleWithPolicy(ctx, SnellerRole+Uid, snellerAwsAccountId, tenant.TenantID, snellerBucket); err != nil {
		return
	}
	log("Created role for sneller bucket   ", roleArn)

	if err = adjustTrustRelationship(ctx, SnellerRole+Uid, fmt.Sprintf("role/tenant-%s", tenant.TenantID)); err != nil {
		return
	}
	log("Adjusted trust relationship       ", "done")

	// Sneller needs to know the ARN of the role in order to assume the cross account IAM role
	if err = setRoleInSneller(tenant, "s3://"+snellerBucket, roleArn); err != nil {
		return
	}
	log("Passed bucket and role to sneller ", "done")

	return
}

func createSnellerRoleWithPolicy(ctx context.Context, roleName, accountId, tenantId, bucketName string) (arn, name string, err error) {

	var resp *iam.CreateRoleOutput
	if resp, err = iamClient.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName:                 aws.String(roleName),
		AssumeRolePolicyDocument: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"` + accountId + `"},"Condition":{"StringEquals":{"sts:ExternalId":"` + tenantId + `"}}}]}`),
	}); err != nil {
		return
	}

	arn = *resp.Role.Arn
	name = roleName

	if _, err = iamClient.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName:       aws.String(roleName),
		PolicyName:     aws.String("sneller-bucket"),
		PolicyDocument: aws.String(`{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Action": "s3:ListBucket","Resource": "arn:aws:s3:::` + bucketName + `","Condition": { "StringLike": { "s3:prefix": "db/*" } }},{"Effect": "Allow","Action": ["s3:PutObject","s3:GetObject","s3:DeleteObject"],"Resource": "arn:aws:s3:::` + bucketName + `/db/*"}]}`),
	}); err != nil {
		return
	}
	return // pass on any errors as is
}

func adjustTrustRelationship(ctx context.Context, roleName, roleTenant string) (err error) {

	var role *iam.GetRoleOutput
	if role, err = iamClient.GetRole(ctx, &iam.GetRoleInput{
		RoleName: aws.String(roleName),
	}); err != nil {
		return
	}

	var updatedPolicy string
	if updatedPolicy, err = url.QueryUnescape(*role.Role.AssumeRolePolicyDocument); err != nil {
		return
	}

	// Adjust trust relationship: remove root account and insert the ARN of the role specifically linked to your org
	// arn:aws:iam::671229366946:root --> arn:aws:iam::671229366946:role/tenant-<<TENANT_ID>>

	updatedPolicy = strings.ReplaceAll(updatedPolicy, `:root"}`, `:`+roleTenant+`"}`)

	// Allow for some time for IAM changes to propagate
	time.Sleep(1500 * time.Millisecond)

	// Retry max five times
	for retry := 0; retry < 5; retry++ {
		_, err = iamClient.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{
			RoleName:       aws.String(roleName),
			PolicyDocument: aws.String(updatedPolicy),
		})
		if err == nil {
			return
		}
		time.Sleep(3000 * time.Millisecond)
	}
	return // pass on any errors as is
}

func setRoleInSneller(tenant TenantInfo, bucketName, roleArn string) (err error) {

	values := url.Values{}
	values.Set("operation", "setBucket")
	values.Set("bucket", bucketName)
	values.Set("roleArn", roleArn)
	values.Set("externalId", tenant.TenantID)

	// Allow for some time for IAM changes to propagate
	time.Sleep(1500 * time.Millisecond)

	// Retry max three times
	for retry := 0; retry < 3; retry++ {
		_, err = invokeSnellerApi("PATCH", "/tenant/"+tenant.TenantID, tenant.TokenSecret, values, nil)
		if err == nil {
			return
		}
		time.Sleep(3000 * time.Millisecond)
	}
	return
}

func setupDataSource(ctx context.Context, snellerRole string, tenant TenantInfo, config SnellerConfig) (err error) {

	policy := `{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Action": "s3:ListBucket","Resource": "arn:aws:s3:::` + config.SourceBucket + `"},{"Effect": "Allow","Action": "s3:GetObject","Resource": "arn:aws:s3:::` + config.SourceBucket + `/*"}]}`
	if config.SourcePath != "" {
		policy = `{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Action": "s3:ListBucket","Resource": "arn:aws:s3:::` + config.SourceBucket + `","Condition": { "StringLike": { "s3:prefix": "` + config.SourcePath + `/*" } }},{"Effect": "Allow","Action": "s3:GetObject","Resource": "arn:aws:s3:::` + config.SourceBucket + `/` + config.SourcePath + `/*"}]}`
	}

	// Attach this policy to "Sneller" role
	if _, err = iamClient.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName:       aws.String(snellerRole),
		PolicyName:     aws.String("sneller-permission-source-" + Uid),
		PolicyDocument: aws.String(policy),
	}); err != nil {
		return
	}
	log("Attached policy to sneller role   ", snellerRole)

	// 3. Create definition.json file in sneller bucket under db / DATABASE / TABLE
	if err = createTableDefinition(tenant, config); err != nil {
		return
	}
	log("Created table definition          ", "done")

	// 4. Setup event notifications
	sqsQueueArn := "arn:aws:sqs:us-east-1:" + SnellerAwsAccountId + ":tenant-sdb-" + tenant.TenantID
	if err = setupEventNotifications(ctx, config.SourceBucket, config.SourcePath+"/", sqsQueueArn); err != nil {
		return
	}
	log("Setup event notifications         ", "done")

	// 5. Initiate sync
	if err = initiateSyncForTable(tenant, "s3://"+config.SourceBucket+"/"+config.SourcePath+"/"+config.SourceWildcard); err != nil {
		return
	}
	log("Initiated sync for table          ", "done")
	return
}

func createTableDefinition(tenant TenantInfo, config SnellerConfig) (err error) {

	type Input struct {
		// Pattern is the glob pattern that
		// specifies which files are fed into
		// the table. Patterns should be URIs
		// where the URI scheme (i.e. s3://, file://, etc.)
		// indicates where the data ought to come from.
		Pattern string `json:"pattern"`
		// Format is the format of the files in pattern.
		// If Format is the empty string, then the format
		// will be inferred from the file extension.
		Format string `json:"format,omitempty"`
	}

	type TableDefinition struct {
		// Name is the name of the table
		// that will be produced from this Definition.
		// Name should match the location of the Definition
		// within the db filesystem hierarchy.
		Name string `json:"name"`
		// Inputs is the list of inputs that comprise the table.
		Inputs []Input `json:"input,omitempty"`
	}

	def := TableDefinition{
		Name: config.Table,
		Inputs: []Input{
			{
				Pattern: "s3://" + config.SourceBucket + "/" + config.SourcePath + "/" + config.SourceWildcard,
				Format:  config.SourceFormat,
			},
		},
	}

	var definition []byte
	if definition, err = json.Marshal(def); err != nil {
		return
	}

	target := fmt.Sprintf("/tenant/%s/db/%s/table/%s/definition", tenant.TenantID, config.Database, config.Table)

	// Allow for some time for IAM changes to propagate
	time.Sleep(1500 * time.Millisecond)

	// Retry max three times
	for retry := 0; retry < 3; retry++ {
		_, err = invokeSnellerApi("PUT", target, tenant.TokenSecret, url.Values{}, bytes.NewReader(definition))
		if err == nil {
			return
		}
		time.Sleep(3000 * time.Millisecond)
	}

	return
}

func setupEventNotifications(ctx context.Context, bucketName, bucketPrefix, sqsQueueArn string) (err error) {

	in := s3.PutBucketNotificationConfigurationInput{
		Bucket: aws.String(bucketName),
		NotificationConfiguration: &types.NotificationConfiguration{
			QueueConfigurations: []types.QueueConfiguration{
				{
					Id:       aws.String("sneller-event"),
					QueueArn: aws.String(sqsQueueArn),
					Events:   []types.Event{"s3:ObjectCreated:*"},
				},
			},
		},
	}

	if bucketPrefix != "" {
		in.NotificationConfiguration.QueueConfigurations[0].Filter = &types.NotificationConfigurationFilter{
			Key: &types.S3KeyFilter{
				FilterRules: []types.FilterRule{
					{
						Name:  types.FilterRuleNamePrefix,
						Value: aws.String(bucketPrefix),
					},
				},
			},
		}
	}

	_, err = s3Client.PutBucketNotificationConfiguration(ctx, &in)
	if err != nil {
		// Output hint as to whether the user actually owns the bucket
		log("Error while configuring bucket notifications", fmt.Sprintf("Do you **own** the bucket: '%s' ?", bucketName))
	}
	return // pass on any errors as is
}

func initiateSyncForTable(tenant TenantInfo, pattern string) (err error) {

	// Initiate sync for this table
	values := url.Values{}
	values.Set("pattern", pattern)
	values.Set("limit", "10")

	// Allow for some time for IAM changes to propagate
	time.Sleep(1500 * time.Millisecond)

	// Retry max five times
	for retry := 0; retry < 5; retry++ {
		_, err = invokeSnellerApi("POST", fmt.Sprintf("/tenant/%s/sync", tenant.TenantID), tenant.TokenSecret, values, nil)
		if err == nil {
			return
		}
		time.Sleep(3000 * time.Millisecond)
	}
	return
}

func getEndpoint() string {
	// Check for sneller's production account
	if SnellerAwsAccountId == "701831592002" {
		return "https://snellerd-production.us-east-1.sneller.io"
	}
	return "https://latest-snellerd-master.us-east-1.sneller-dev.io"
}
