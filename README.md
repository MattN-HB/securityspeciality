# AWS Security Speciality Cert
This repo is a guide to taking security speciality cert in 2021. The AWS website is [here](https://aws.amazon.com/certification/certified-security-specialty/).

## My Key Resources: 
* [acloudguru hands on course](https://acloudguru.com/course/aws-certified-security-specialty)

## Scoring
<details>
  <summary>Expand</summary>
  
* 100 - 1000 with minimum 720
* scaled scoring model
* 15 unscored questions that do not affect your score
* Unanswered questions are scored as incorrect; there is no penalty for guessing
* Multiple-choice: Has one correct response and three incorrect responses (distractors).
* Multiple-response: Has two or more correct responses out of five or more options
</details>

## Domain Breakdown 
<img width="807" alt="image" src="https://user-images.githubusercontent.com/44328319/133793047-a5f83399-c53b-4bbb-b12f-322619eb123f.png">

<details>
  <summary>Domain 1: Incdident Response </summary>
    1.1 Given an AWS abuse notice, evaluate the suspected compromised instance or exposed access keys.
  
    * Given an AWS Abuse report about an EC2 instance, securely isolate the instance as part of a forensic investigation.
    * Analyze logs relevant to a reported instance to verify a breach, and collect relevant data.
    * Capture a memory dump from a suspected instancefor later deep analysis or for legal compliance reasons.
  
    1.2 Verify that the Incident Response plan includes relevant AWS services.
  
    * Determine if changes to baseline security configuration have been made.
    * Determine if list omits services,processes, or procedures which facilitate Incident Response.
    * Recommend services, processes, procedures to remediate gaps.
  
    1.3 Evaluate the configuration of automated alerting, and execute possible remediation of security-related incidents and emerging issues.
  
    * Automate evaluation of conformance with rules for new/changed/removed resources.
    * Apply rule-based alerts for common infrastructure misconfigurations.
    * Review previous security incidents and recommend improvements to existing systems
</details>

## Areas Covered
<details>
  <summary>Types</summary>


</details>

  
## Resources
<details>
    <summary>Expand</summary>
  
* 
 </details>  

## CLI Helpful Commands
<details>
  <summary>Expand</summary>
  
* ```aws configure```
* Copies file from local to bucket```aws s3 cp <path> s3://<bucket>```
* List buckets```aws s3 ls```
* List Bucket Content: ```aws s3 ls s3://<bucket>```
* Create s3 bucket ```aws s3api create-bucket --bucket <bucketname> --region us-east-1```
* grab your environment variables from cli ```env | grep ^AWS```
* What is the policies attached to that user ```aws iam list-attached-user-policies --user-name=$AWS_ACCOUNT_USERNAME```
* Create iam user ```aws iam create-user --user-name root-for-vault```
* Attach policy ```aws iam attach-user-policy --user-name root-for-vault --policy-arn arn:aws:iam::${AWS_ACCOUNT_ID}:policy/vault-root```
* Create access key and secret passing to txt for temp use ```aws iam create-access-key --user-name root-for-vault | tee root-for-vault-keys.txt```
* Set default region ```export AWS_DEFAULT_REGION=us-east-1```
* Create VPC ```aws ec2 create-default-vpc```
* Run EC2 ```aws ec2 run-instances --image-id <amiid> --instance-type <ec2type> --count 1```
* List RDS ```aws rds describe-db-instances```
* Grab metadata from instance ```curl http://169.254.169.254/latest/meta-data/``` ```wget http://169.254.169.254/latest/meta-data/```
* Grab userdata from instance ```curl http://169.254.169.254/latest/user-data/```
* List lambda functions ```aws lambda list-functions --max-items 10```  [Full list of lambda cli ](https://docs.aws.amazon.com/cli/latest/reference/lambda/index.html)
* Invoke Lambda ```aws lambda invoke \
    --function-name my-function \
    --payload '{ "name": "Bob" }' \
    response.json```
* Delete an S3 bucket and all its contents with just one command 
`aws s3 rb s3://bucket-name -force`
* Copy a directory and its subfolders from your PC to Amazon S3 
`aws s3 cp MYFolder s3://bucket-name -recursive [-region us-west-2]`
* Display subsets of all available ec2 images 
`aws ec2 describe-images | grep ubuntu`
* List users in a different format 
`aws iam list-users --output table`
* Get credentialed IAM reports from CLI `aws iam generate-credential-report` and read it `aws iam get-credential-report --output text | base64 --decode >> credentialreport.csv`
* List the sizes of an S3 bucket and its contents 
`aws s3api list-objects --bucket BUCKETNAME --output json --query " 
[sum(Contents[].Size), length(Contents[])]"`
* Move S3 bucket to a different location 
`aws s3 sync s3://oldbucket s3://newbucket --source-region us-west-l 
--region us-west-2`
* sync files from local but exlude some directories and .pem `aws s3 sync <YOURLOCALPATH> s3://<YOURBUCKETNAME> --exclude 'scripts/*' --exclude '*.pem'`
* List users by ARN 
`aws iam list-users --output json | jq -r .Users[].Arn`
* List all of your instances that are currently running
`aws ec2 describe-instances --filters Name=instance-state-name,Values=running --query 'Reservations[*].Instances[].[InstanceId,State,PublicIpAddress, Tags[?Key==`Name`].Value]' --region us-east-1 --output json | jq `
`aws ec2 describe-instances --filters Name=instance-state-name,Values=running --region us-east-1 --output table`
* start ec2 instances `aws ec2 start-instances --instance-ids <your instance id>`
* describe your sg rules `aws ec2 describe-security-group-rules`
* Other ways to pass input parameters to the AWS CLI with JSON 
`aws iam put-user-policy --user-name AWS-Cli-Test --policy-name 
Power-Access --policy-document { "Statement":[{ "Effect": 
"Allow" , "NotAction":"iam:*", "Resource": "*"} ] }`
* When backups complete send to sns topic `aws backup put-backup-vault-notifications --endpoint-url https://backup.eu-west-1.amazonaws.com --backup-vault-name examplevault --sns-topic-arn arn:aws:sns:eu-west-1:111111111111:exampletopic --backup-vault-events BACKUP_JOB_COMPLETED`
* Get backups notifications `aws backup get-backup-vault-notifications --backup-vault-name examplevault`
</details>

## My Personal Cheat Sheet / Takeways
 <details>
    <summary>Expand</summary>
   
 * 
   
 </details>  

