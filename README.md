## AWS Multi-Account IAM User Provisioning via STS & Lambda

## 📘 Overview

This solution enables centralized IAM user creation across **100+ independent AWS accounts** using a **parent account**. It leverages **AWS Lambda**, **AWS CFT** **STS AssumeRole**, and **S3 logging** to provision IAM users with EC2 and CloudWatch access in each child account, while maintaining a secure and auditable log of operations.

> ✅ This solution does **not** require AWS Organizations. It works across **multiple standalone AWS accounts**.

---
##  Architecture

###  Child Accounts (Secondary accounts)

- **CFT**: Create a cloud formation template to create role in child account to allow parent aws accounts to assume that role
- **IAM Role**: Trusted by the parent account to allow `sts:AssumeRole`.
- **Permissions**: Allows creation of IAM users and attachment of EC2 and CloudWatch policies.

---


###  Parent Account (Master Account)
- **Lambda Function**: Orchestrates IAM user creation across child accounts.
- **S3 Bucket**: Stores logs with:
  - `Account ID`
  - `Username`
  - `Temporary Password`
  - `Creation Status` (`Created`, `Exists`, `Failed`)
- **STS AssumeRole**: Uses `sts:AssumeRole` to gain temporary access to child accounts.

## ⚙️ Workflow

1. **Trigger Lambda**: Parent account invokes Lambda with target child account ID and desired username.
2. **Assume Role via STS**: Lambda uses `sts:AssumeRole` to gain temporary credentials for the child account.
3. **Create IAM User**:
   - If user already exists → log `Exists`
   - If creation succeeds → attach EC2 & CloudWatch policies, log `Created`
   - If creation fails → log `Failed`
4. **Log to S3**: All outcomes are stored in a centralized S3 bucket for audit and tracking.

---

## Security Considerations

-  IAM roles in child accounts should follow least privilege principles.
-  S3 bucket should have encryption, versioning, and access logging enabled.
-  Lambda should validate inputs and sanitize usernames.
-  Temporary credentials from STS should be short-lived and scoped.

## Use Cases

- **DevOps Onboarding** : Provision EC2 and monitoring access for new engineers across accounts.
- **Security Isolation** : Maintain separate AWS accounts while managing users centrally.
- **Audit & Compliance** : Track user creation status and credentials in a secure S3 bucket.
- **Automation** : Reduce manual IAM provisioning across accounts with a single Lambda trigger.

## What This Solution Achieves

-  Centralized IAM provisioning across multiple AWS accounts
-  Secure, auditable logging of user creation status
-  Automated assignment of EC2 and CloudWatch access
-  Scalable and organization-independent architecture
-  Reduced operational overhead and human error

## Last thing which I want to say Keep Working on Yourself.
