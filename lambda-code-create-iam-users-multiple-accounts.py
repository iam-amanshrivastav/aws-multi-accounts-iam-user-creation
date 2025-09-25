#### Lambda code for creating IAM users from parent account to AWS child accounts assuming role which were created by CFT

```
import boto3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import logging
import io
import secrets
import string
import csv

# ---------- CONFIGURATION ----------
SECONDARY_ACCOUNTS = ["12345XYZ"]  # Add more accounts if needed
ROLE_NAME = "CloudOpsRole" # Mentioned the role name
BUCKET_NAME = "automation-work-logs" # Mentioned the bucket name in which logs are going to stored
MAX_WORKERS = 5
USER_NAME = "ec2andcloudwatch"  # User-provided name

# ---------- LOGGING ----------

logger = logging.getLogger()
logger.setLevel(logging.INFO)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(stream_handler)

# ---------- UTILITY FUNCTIONS ----------

def assume_role(account_id):
    sts_client = boto3.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{ROLE_NAME}"
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="CloudOpsSession"
        )
        creds = response["Credentials"]
        logger.info(f"Assumed role in account {account_id}")
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )
    except Exception as e:
        logger.error(f"Failed to assume role in account {account_id}: {e}")
        return None

def generate_password(length=12):
    """Generate a random password for console login"""
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(secrets.choice(chars) for _ in range(length))

def create_iam_user(session, account_id, user_name, log_buffer):
    result = {"AccountID": account_id, "UserName": user_name, "Status": "", "Password": "", "MFARequired": "No"}
    iam_client = session.client("iam")
    try:
        # Check if user exists
        try:
            iam_client.get_user(UserName=user_name)
            msg = f"{account_id}: User {user_name} already exists, please use a different name"
            logger.info(msg)
            log_buffer.write(msg + "\n")
            result["Status"] = "EXISTS"
            return result
        except iam_client.exceptions.NoSuchEntityException:
            pass  # User does not exist, proceed

        # Create user
        iam_client.create_user(UserName=user_name)
        msg = f"{account_id}: User {user_name} created successfully"
        logger.info(msg)
        log_buffer.write(msg + "\n")
        result["Status"] = "CREATED"

        # Optional: create console login profile
        password = generate_password()
        try:
            iam_client.create_login_profile(
                UserName=user_name,
                Password=password,
                PasswordResetRequired=False  # Optional, user can log in directly
            )
            result["Password"] = password
            msg = f"{account_id}: Console login created for {user_name} with temporary password"
            logger.info(msg)
            log_buffer.write(msg + "\n")
        except iam_client.exceptions.EntityAlreadyExistsException:
            msg = f"{account_id}: Login profile already exists for {user_name}"
            logger.info(msg)
            log_buffer.write(msg + "\n")

        # Attach policies
        iam_client.attach_user_policy(
            UserName=user_name,
            PolicyArn="arn:aws:iam::aws:policy/AmazonEC2FullAccess"
        )
        iam_client.attach_user_policy(
            UserName=user_name,
            PolicyArn="arn:aws:iam::aws:policy/CloudWatchFullAccess"
        )
        msg = f"{account_id}: Attached EC2 & CloudWatch full access to {user_name}"
        logger.info(msg)
        log_buffer.write(msg + "\n")

    except Exception as e:
        msg = f"{account_id}: User {user_name} creation failed: {str(e)}"
        logger.error(msg)
        log_buffer.write(msg + "\n")
        result["Status"] = f"FAILED: {str(e)}"

    return result

def upload_to_s3_memory(file_content, bucket, key):
    s3 = boto3.client("s3")
    try:
        s3.put_object(Bucket=bucket, Key=key, Body=file_content.getvalue())
        logger.info(f"Uploaded to s3://{bucket}/{key}")
    except Exception as e:
        logger.error(f"Failed to upload to S3: {e}")

# ---------- MAIN FUNCTION ----------
def main():
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")
    csv_buffer = io.StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerow(["AccountID", "UserName", "Status", "TemporaryPassword", "MFARequired"])

    log_buffer = io.StringIO()

    def process_account(account_id):
        session = assume_role(account_id)
        if not session:
            msg = f"{account_id}: Could not assume role, skipping"
            logger.error(msg)
            log_buffer.write(msg + "\n")
            writer.writerow([account_id, USER_NAME, "FAILED: Could not assume role", "", "No"])
            return
        result = create_iam_user(session, account_id, USER_NAME, log_buffer)
        writer.writerow([result["AccountID"], result["UserName"], result["Status"], result.get("Password", ""), result["MFARequired"]])

    # Multi-threaded for multiple accounts
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(process_account, acc) for acc in SECONDARY_ACCOUNTS]
        for future in futures:
            future.result()  # wait for all

    # Upload CSV report to S3
    csv_key = f"reports/iam-user-report-{timestamp}.csv"
    upload_to_s3_memory(csv_buffer, BUCKET_NAME, csv_key)

    # Upload detailed logs to S3
    log_key = f"logs/iam-user-log-{timestamp}.txt"
    upload_to_s3_memory(log_buffer, BUCKET_NAME, log_key)

# ---------- LAMBDA HANDLER ----------
def lambda_handler(event, context):
    try:
        main()
        return {
            "statusCode": 200,
            "body": "IAM user automation executed successfully"
        }
    except Exception as e:
        return {
            "statusCode": 500,
            "body": f"Error executing automation: {str(e)}"
        }

```

