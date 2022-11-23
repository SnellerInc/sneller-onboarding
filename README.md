# Intro

Script to setup the required permission and role for cross-account access for Sneller.

# Prerequisites

* golang installed
* valid AWS access credentials (IAM and S3 services)

# Existing tenant

Use an existing tenant:
```
export         TENANT_ID="TA..."                     # ID of tenant
export     TENANT_SECRET="SA..."                     # Token secret of tenant
export  SNELLER_DATABASE="test"
export     SNELLER_TABLE="demo"
export     SOURCE_BUCKET="s3://my-source-bucket"     # no trailing slash
export       SOURCE_PATH="my/data/directory"         # no leading or trailing slash
export   SOURCE_WILDCARD="*.json.gz"
export     SOURCE_FORMAT="json.gz"
```

Run the script:
```
go run sneller-onboarding.go
```

# Sample output

```
$ go run sneller-onboarding.go
Created new tenant                : TA0M1364NN62
Created sneller bucket            : sneller-ta0m1364nn62
Created role for sneller bucket   : arn:aws:iam::874202789198:role/sneller-role-eebc8a8
Adjusted trust relationship       : done
Passed bucket and role to sneller : done
Attached policy to sneller role   : sneller-role-eebc8a8
Created table definition          : done
Setup event notifications         : done
Initiated sync for table          : done
==================================:
sneller endpoint: https://snellerd-production.us-east-1.sneller.io
           token: SA0...<redacted>
        database: test
           table: demo
           query: curl -s -G --data-urlencode "query=SELECT COUNT(*) FROM demo" \
                    --data-urlencode "database=test" --data-urlencode "json" \
                    -H "Authorization: Bearer SA0...<redacted>" 'https://snellerd-production.us-east-1.sneller.io/executeQuery'
$
$ curl -s -G --data-urlencode "query=SELECT COUNT(*) FROM demo" \
    --data-urlencode "database=test" --data-urlencode "json" \
    -H "Authorization: Bearer SA0...<redacted>" 'https://snellerd-production.us-east-1.sneller.io/executeQuery'
{"count": 84922}
```

# Command line arguments

Pass in `--json` to get the output in JSON, like so: `go run sneller-onboarding.go --json`

# New tenant or sub-tenant

To configure a new tenant (pass in token for parent tenant to create sub-tenant):
```
export      MASTER_TOKEN="SA...."
export   TENANT_ORG_NAME="Acme Corp"                 # name of organization for tenant
export      TENANT_EMAIL="your-email@email.com"
export  SNELLER_DATABASE="test"
export     SNELLER_TABLE="demo"
export     SOURCE_BUCKET="s3://my-source-bucket"     # no trailing slash
export       SOURCE_PATH="my/data/directory"         # no leading or trailing slash
export   SOURCE_WILDCARD="*.json.gz"
export     SOURCE_FORMAT="json.gz"
```
