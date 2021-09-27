# AWS Security Speciality Cert
This repo is **my personal** guide to taking security speciality cert in 2021. The AWS website is [here](https://aws.amazon.com/certification/certified-security-specialty/).

## My Key Resources: 
* [acloudguru hands on course](https://acloudguru.com/course/aws-certified-security-specialty)
* [Tutorial Dojo Practice Exams](https://portal.tutorialsdojo.com/courses/aws-certified-security-specialty-practice-exams/lessons/practice-exams-timed-mode-7/)

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
  <summary>Domain 1: Incident Response </summary>
  
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
<details>
  <summary>Domain 2: Logging and Monitoring </summary>
  
2.1 Design and implement security monitoring and alerting.
* Analyze architecture and identify monitoring requirements and sources for monitoring statistics.
* Analyze architecture to determine which AWS services can be used to automate monitoring and alerting.*
* Analyze the requirements for custom application monitoring, and determine how this could be achieved.
* Setup automated tools/scripts to perform regular audits.
Version 2.0SCS-C014|P A G E

2.2 Troubleshoot security monitoring and alerting.
* Given an occurrence of a known event without the expected alerting, analyze the service functionality and configuration andremediate.
* Given an occurrence of a known event without the expected alerting, analyze the permissions and remediate.
* Given a custom application which is not reporting its statistics, analyze the configuration and remediate.
* Review audit trails of system and user activity.

2.3 Design and implement a logging solution.
* Analyze architecture and identify logging requirements and sources for log ingestion.
* Analyze requirements and implement durable and secure log storage according to AWS best practices.
* Analyzearchitecture to determine which AWS services can be used to automate log ingestion and analysis.

2.4Troubleshoot logging solutions.
* Given the absence of logs, determine the incorrect configuration and define remediation steps.
* Analyze logging access permissions to determine incorrect configuration and define remediation steps.
* Based on the security policy requirements, determine the correct log level, type, and sources
</details>


<details>
  <summary>Domain 3: Infrastructure Security </summary>
  
3.1 Design edge security on AWS.
* For a given workload, assess and limit the attack surface.
* Reduce blast radius (e.g. by distributing applications across accounts and regions).
* Choose appropriate AWS and/or third-party edge services such as WAF, CloudFront and Route53 to protect against DDoS or filter application-level attacks.
* Given a set of edge protection requirements for an application, evaluate the mechanisms to prevent and detect intrusions for compliance and recommend required changes.
* Test WAF rules to ensure they block malicious traffic.

3.2 Design and implement a secure network infrastructure.
* Disable any unnecessary network ports and protocols.
* Given a set of edge protection requirements, evaluate the security groups and NACLs of an application for compliance and recommend required changes.
* Given security requirements, decide on network segmentation (e.g. security groups and NACLs) that allow the minimum ingress/egress access required.
* Determine the use case for VPN or Direct Connect.Determine the use case for enabling VPC Flow Logs.
* Given a description of the network infrastructure for a VPC, analyze the use of subnets and gateways for secure operation.

3.3 Troubleshoot a secure network infrastructure.
* Determine where network traffic flow is being denied.
* Given a configuration,confirm security groups and NACLs have been implemented correctly.


3.4 Design and implement host-based security.
* Given security requirements, install and configure host-based protections including Inspector, SSM.
* Decide when to use host-based firewall like iptables.Recommend methods for host hardening and monitoring.  
</details>

<details>
  <summary>Domain 4: Identity and Access Management </summary>
  
4.1 Design and implement a scalable authorization and authentication system to access AWS resources.
* Given a description of a workload, analyze the access control configuration for AWS services and make recommendations that reduce risk.
* Given a description how an organization manages their AWS accounts, verify security of their root user.
* Given your organization’s compliance requirements, determine when to apply user policies and resource policies.
* Within an organization’s policy, determine when to federate a directory services to IAM.
* Design a scalable authorization model that includes users, groups, roles, and policies.
* Identify and restrict individual users of data and AWS resources.
* Review policies to establish that users/systems are restricted from performing functions beyond their responsibility, and also enforce proper separation of duties.

4.2 Troubleshoot an authorization and authentication system to access AWS resources.
* Investigate a user’s inability to access S3 bucket contents.
* Investigate a user’s inability to switchroles to a different account.
* Investigate an Amazon EC2 instance’s inability to access a given AWS resource

</details>
<details>
  <summary>Domain 5: Data Protection</summary>
  
5.1 Design and implement key management and use.
* Analyze a given scenario to determine an appropriate key management solution.
* Given a set of data protection requirements, evaluate key usage and recommend required changes.
* Determine and control the blast radius of a key compromise event and design a solution to contain the same.

5.2 Troubleshoot key management.
* Breakdown the difference between a KMS key grant and IAM policy.
* Deduce the precedence given different conflicting policies for a given key.
* Determine when and how to revoke permissions for a user or service in the event of a compromise.

5.3 Design and implement a data encryption solution for data at rest and data in transit.
* Given a set of data protection requirements, evaluate the security of the data at rest in a workload and recommend required changes.
* Verify policy on a key such that it can only beused by specific AWS services.
* Distinguish the compliance state of data through tag-based data classifications and automate remediation.
* Evaluate a number of transport encryption techniques and select the appropriate method (i.e. TLS, IPsec, client-side KMS encryption).
</details>

## Areas Covered/Tips
<details>
  <summary>AWS Shared Responsibility</summary>
  
  <img width="406" alt="image" src="https://user-images.githubusercontent.com/44328319/133936461-073ed22c-8298-4232-aac8-375968e5e2ac.png">
  <img width="1045" alt="image" src="https://user-images.githubusercontent.com/44328319/133936239-673da30a-479b-45ec-8d0e-907ac5546118.png">
  <img width="1265" alt="image" src="https://user-images.githubusercontent.com/44328319/133936186-4f2fd92a-c589-42fe-b712-bb8852d28749.png">
  <img width="241" alt="image" src="https://user-images.githubusercontent.com/44328319/133936265-a9281a8f-e848-4572-8365-36a048b3a1d6.png">

</details>
<details>
  <summary>IAM</summary>
    
  <img width="245" alt="image" src="https://user-images.githubusercontent.com/44328319/133936280-baf4f25d-83a5-4c98-be57-d3f7f8c6b258.png">
  <img width="240" alt="image" src="https://user-images.githubusercontent.com/44328319/133936293-d03014fd-94bc-4e94-8dcb-4c7f756d3dff.png">
  <img width="225" alt="image" src="https://user-images.githubusercontent.com/44328319/133936304-a06c2b3f-7cee-4119-9358-ebc89f913361.png">
 
</details>
 
<details>
  <summary>Bucket Policies, and Cross Region Replication (CRR)</summary>
  
  <img width="251" alt="image" src="https://user-images.githubusercontent.com/44328319/133936329-c50e8a26-fd61-4e43-a4a0-41056574ccf2.png">
  <img width="423" alt="image" src="https://user-images.githubusercontent.com/44328319/133936341-c793ed62-3ffd-42bd-bd5e-1dafdc52983e.png">
  <img width="359" alt="image" src="https://user-images.githubusercontent.com/44328319/133936469-877b6c3d-31fa-4ee9-bc6e-819b84bbaf0e.png">
  <img width="403" alt="image" src="https://user-images.githubusercontent.com/44328319/133936353-34a502f4-0da7-4978-a27a-f1610d3c5c09.png">
  <img width="371" alt="image" src="https://user-images.githubusercontent.com/44328319/133936490-9e13d487-1f2d-46d1-aaab-e751aae3193b.png">
  <img width="413" alt="image" src="https://user-images.githubusercontent.com/44328319/133936356-8679fda4-dfed-44ec-8c83-caff89c65c62.png">
  <img width="412" alt="image" src="https://user-images.githubusercontent.com/44328319/133936369-8f69d8d2-e847-4c03-a64a-e4145a40df8d.png">
  <img width="335" alt="image" src="https://user-images.githubusercontent.com/44328319/133936499-8512bf7e-cb79-4bd8-9832-f77bbdfd0c1a.png">
  <img width="398" alt="image" src="https://user-images.githubusercontent.com/44328319/133936502-8f041410-2519-49cd-a312-d5e2a1e2461d.png">
    
</details>
<details>
  <summary>Cloudfront, S3 OAI, Custom SSL Certs, Presigned Urls</summary>
  Steps to set up OAI see below in order for exam
  <img width="536" alt="image" src="https://user-images.githubusercontent.com/44328319/134004317-09945c2d-4bf7-4d7f-88c6-640c35829d11.png">  
  <img width="1081" alt="image" src="https://user-images.githubusercontent.com/44328319/134005268-b56b0dc0-210b-44d8-8682-c768ad23dd64.png">
  <img width="1141" alt="image" src="https://user-images.githubusercontent.com/44328319/134006453-5ee89c7b-7bb6-4e34-8574-4f07d60e5601.png">

</details>
<details>
  <summary>STS, Cognito pools, Glacier Vault,Orgs,and Credential Reports</summary>
  <img width="611" alt="image" src="https://user-images.githubusercontent.com/44328319/134177190-5567ee95-563e-43de-8aa2-65c15dbfa736.png">
  <img width="611" alt="image" src="https://user-images.githubusercontent.com/44328319/134177234-b1c82b20-9510-4e2e-a5ee-6e36808295f8.png">
  <img width="352" alt="image" src="https://user-images.githubusercontent.com/44328319/134177302-310ef83a-e25b-4485-8d0c-9d0ce7a1fa92.png">
  <img width="627" alt="image" src="https://user-images.githubusercontent.com/44328319/134177350-19668af6-19c7-4765-9c6c-85df590ec6c8.png">
  <img width="624" alt="image" src="https://user-images.githubusercontent.com/44328319/134177401-2a75ad3e-0547-4e11-ba69-c39b639f02f2.png">
  <img width="613" alt="image" src="https://user-images.githubusercontent.com/44328319/134177462-2009703b-28f4-4dae-939f-a366b84f9593.png">
  <img width="631" alt="image" src="https://user-images.githubusercontent.com/44328319/134177510-bca8e43d-fbf6-4880-a3b9-2b4e0e07ac94.png">
  <img width="631" alt="image" src="https://user-images.githubusercontent.com/44328319/134177569-5583daf4-6f01-4cfa-b20c-0067ae88133b.png">
  <img width="643" alt="image" src="https://user-images.githubusercontent.com/44328319/134177601-68a1c46b-de9f-434b-a559-2caadc039e72.png">
  <img width="597" alt="image" src="https://user-images.githubusercontent.com/44328319/134177653-951837ef-ca2b-47cf-988e-7e02f5d7a1c7.png">


</details>
<details>
  <summary>Cloudtrail</summary>
  
  ![image](https://user-images.githubusercontent.com/44328319/134353748-9207bda6-d8d5-401f-b96a-bb3db1ee2a91.png)
  This does not log RDP/SSH sessions.
  ![image](https://user-images.githubusercontent.com/44328319/134354253-56bb2df9-9da8-4b89-8ce9-d2185f534414.png)
  ![image](https://user-images.githubusercontent.com/44328319/134354152-9cac7580-40fa-4f4d-8cf7-6af808cc258e.png)
  ![image](https://user-images.githubusercontent.com/44328319/134354337-0e3760a7-ea9f-44f6-8695-ee01d25e57b8.png)
  ![image](https://user-images.githubusercontent.com/44328319/134354487-16e7ce82-224b-431b-a19e-6c404db27676.png)   
  ![image](https://user-images.githubusercontent.com/44328319/134354537-0478a2e5-6dde-429d-85e1-651617a045e7.png)

 </details>  
 <details>
  <summary>Cloudwatch</summary>
  
  ![image](https://user-images.githubusercontent.com/44328319/134354953-e861b9e6-f53a-454c-ba03-43e4507f896b.png)
  ![image](https://user-images.githubusercontent.com/44328319/134354974-dece39f9-456a-4979-8775-7431f6c06e75.png)
  ![image](https://user-images.githubusercontent.com/44328319/134355060-7374ea41-c2fa-45d3-bfa4-b203a6aecc51.png)
 </details>  
 
  <details>
  <summary>Config</summary>
  
  ![image](https://user-images.githubusercontent.com/44328319/134355480-f8260ca1-5c23-4245-8e86-3f56b7963849.png)
  ![image](https://user-images.githubusercontent.com/44328319/134355527-938d035d-43b1-420e-af31-40efa28742dc.png)
  ![image](https://user-images.githubusercontent.com/44328319/134357716-e6c1162a-51c3-4553-bcdb-b1632d671b63.png)
  Know when to use above 
  
  ![image](https://user-images.githubusercontent.com/44328319/134357918-6dbf2028-5394-4da5-9e11-2356c6046b83.png)

 </details>  
 
 <details>
  <summary>Cloud HSM</summary>
 
  ![image](https://user-images.githubusercontent.com/44328319/134356717-1894bb5d-c212-4f19-9e51-f3eaf9c7487a.png)
  ![image](https://user-images.githubusercontent.com/44328319/134356904-f1e839b0-68e8-4ce6-8ea7-dc6b77cb5979.png)

 </details>  
 
  <details>
  <summary>Inspector vs Trusted Advisor</summary>
  
  ![image](https://user-images.githubusercontent.com/44328319/134357323-a55d80f5-b971-4e8d-92f0-2c93b62590e8.png)
  ![image](https://user-images.githubusercontent.com/44328319/134357385-ad75126d-333d-4474-9e63-8f6e7a04452b.png)
  ![image](https://user-images.githubusercontent.com/44328319/134357489-a6edee5e-ed2a-49d4-a8ed-ee90fad994df.png)
  ![image](https://user-images.githubusercontent.com/44328319/134357436-fd648385-765a-480b-a687-bb985e48e55a.png)

 </details>  
 
 <details>
  <summary>KMS</summary>
  
  <img width="915" alt="image" src="https://user-images.githubusercontent.com/44328319/134982143-d14e1371-73e1-46c5-9fef-4f5db1ed8e42.png">
  <img width="790" alt="image" src="https://user-images.githubusercontent.com/44328319/134982184-a46e0d3c-fe43-4cd6-a669-5109345de917.png">
  <img width="882" alt="image" src="https://user-images.githubusercontent.com/44328319/134982250-a0739e5d-417f-40ac-aaf0-90691b334e36.png">
  <img width="834" alt="image" src="https://user-images.githubusercontent.com/44328319/134982276-45ded481-e84c-4710-9555-17823be46e1e.png">
  <img width="807" alt="image" src="https://user-images.githubusercontent.com/44328319/134982313-0c9fb5a9-6d04-43f4-85b7-90cb2cd64d66.png">
  <img width="740" alt="image" src="https://user-images.githubusercontent.com/44328319/134982438-64d3a19d-d755-4b04-ad87-206d289d166e.png">
  <img width="696" alt="image" src="https://user-images.githubusercontent.com/44328319/134982386-28967bba-3714-46ad-b879-1086ed9995cd.png">
  <img width="976" alt="image" src="https://user-images.githubusercontent.com/44328319/134982547-3ba32560-ff2c-4d8d-9257-76dc3b361639.png">
  <img width="959" alt="image" src="https://user-images.githubusercontent.com/44328319/134982626-76a29879-5145-4e27-9e10-e1aa071a07b0.png">
  <img width="1063" alt="image" src="https://user-images.githubusercontent.com/44328319/134982777-14d3da6f-bdd3-407b-8fff-79764ffff56e.png">
  <img width="1049" alt="image" src="https://user-images.githubusercontent.com/44328319/134982810-2ee1beb3-5303-43ee-8739-98babc2b66c1.png">
  <img width="1054" alt="image" src="https://user-images.githubusercontent.com/44328319/134983007-a5fd2766-590e-4bbe-95ec-ed423f9389ca.png">
  <img width="961" alt="image" src="https://user-images.githubusercontent.com/44328319/134983883-57618652-2003-4f7b-8ea7-76e7eab5f7ea.png">
  <img width="905" alt="image" src="https://user-images.githubusercontent.com/44328319/134984026-715c4a08-4e49-4350-8fdb-c324ad6cffc3.png">
  get your public key pair
  <img width="1099" alt="image" src="https://user-images.githubusercontent.com/44328319/134984154-00abd6ce-e00b-4d28-8a72-c5074a0ff6c3.png">
  <img width="1125" alt="image" src="https://user-images.githubusercontent.com/44328319/134984193-3110b949-a6ca-4a6a-a39b-95afb6e28619.png">
  <img width="991" alt="image" src="https://user-images.githubusercontent.com/44328319/134984450-ed1734bb-1b48-4da7-a44b-f5bb091180c0.png">
  <img width="931" alt="image" src="https://user-images.githubusercontent.com/44328319/134984503-59e6ed8b-ed34-4cfd-8ab8-f4aed89c65c7.png">


 </details>  
  
 <details>
  <summary>Marketplace</summary>
  
  <img width="958" alt="image" src="https://user-images.githubusercontent.com/44328319/134985229-dd43c489-b3dc-4b0a-906e-9229c6472d3e.png">
 </details>  
 
  <details>
  <summary>WAF and Shield</summary>
  
   <img width="916" alt="image" src="https://user-images.githubusercontent.com/44328319/134986346-6c41e277-8a4a-4b2c-b070-61227e10529b.png">
   <img width="995" alt="image" src="https://user-images.githubusercontent.com/44328319/134986364-fd12866c-615a-4cbc-9c8c-5b3b89f63bd9.png">
   <img width="976" alt="image" src="https://user-images.githubusercontent.com/44328319/134986449-b52cee59-9c8a-4698-b4c2-c801190f1072.png">
   <img width="998" alt="image" src="https://user-images.githubusercontent.com/44328319/134986498-d091b3b8-06b9-44ad-812a-467cdb3f78d3.png">
  
 </details> 
 
 <details>
  <summary>Dedicated instances vs hosts</summary>
  
  <img width="601" alt="image" src="https://user-images.githubusercontent.com/44328319/134986682-d6eea621-10e9-44fb-a446-a2a46de739c9.png">
  <img width="944" alt="image" src="https://user-images.githubusercontent.com/44328319/134986721-766afbde-ab41-4d99-a8b2-043d6781cde4.png">

 </details> 
 
  <details>
  <summary>Hypervisor</summary>

 </details> 
 
## Resources
<details>
    <summary>Expand</summary>
 
* [Cloudtrail Supported services](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-aws-service-specific-topics.html)
 </details> 
 * [WAF cloudformation](https://s3.amazonaws.com/cloudformation-examples/community/common-attacks.json)

## CLI Helpful Commands
<details>
  <summary>Expand</summary>
  
* ```aws configure```
* presigned url `aws s3 presign s3://url --expires-in 300`
* Copies file from local to bucket```aws s3 cp <path> s3://<bucket>```
* List buckets```aws s3 ls```
* List Bucket Content: ```aws s3 ls s3://<bucket>```
* How get canicol names via cli `aws s3api list-buckets`
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
   
 * 2 services to check ssh open: Config and Trusted Advisor
 * Visibility = Config
 * Multi tenant key service = KMS
 * Customer Shared Responsibility = Configure IAM and apply sec updates
 * 2 services automate tech tasks to avoid human erorr = ops works and codedeploy
 * Principal in IAM permissions = user, account, service to allow or deny
 * Service control Policies = guardrail and org units accesses
 * AWS API used to AD = STS 
 * Temp access to object = presigned url 
 * Permission Boundaries = used to limit max permissions for user roles or users
 * custom ssl needs be in stored in us-east1 cert store
 * Vault lock = can't be changed when implemented
 * AD federation = users must navigate to ADFS signin and users do not need IAM creds
 * Steps cross region replication = owner destination bucket grants source owner via bucket policy permission to replicate
 * Cloudwatch = log aggregation, resource utilization, trigger lambda
 * What inspector package checks for root login over ssh: security best practices and CIS.
 * Cloudfront are global ALB wafs are regional
   
 </details>  

