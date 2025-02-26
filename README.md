# PTE Questions Application Deployment Guide

## AWS-based Serverless Architecture with Authentication

This guide documents the step-by-step process for deploying a serverless PTE (Pearson Test of English) Questions application on AWS using EC2 as the deployment environment. The application features role-based authentication with separate admin and user access levels.

---

## Deployment Environment Setup

### Step 1: Launch an EC2 Linux 2 Instance

1. Log into AWS Management Console
2. Navigate to EC2 service
3. Click "Launch Instance"
4. Select "Amazon Linux 2 AMI"
5. Choose instance type (t2.micro or larger recommended)
6. Configure Security Groups:
    
    ```
    Copy
    Allow SSH (port 22) from your IP
    Allow HTTP (port 80) and HTTPS (port 443)
    
    ```
    
7. Create or select an existing key pair
8. Launch the instance and connect via SSH:
    
    ```bash
    bash
    Copy
    ssh -i your-key.pem ec2-user@your-ec2-public-ip
    
    ```
    

### Step 2: Install Prerequisites

```bash
bash
Copy
# Update the system
sudo yum update -y

# Install development tools
sudo yum install -y git make gcc-c++ unzip

# Install Node.js 14
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.38.0/install.sh | bash
source ~/.bashrc
nvm install 14
node -v  # Verify Node.js installation

# Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
aws --version  # Verify AWS CLI installation

# Create a project directory
mkdir -p ~/pte-app
cd ~/pte-app

```

### Step 3: Configure AWS CLI

Set up your AWS credentials with appropriate permissions:

```bash
bash
Copy
aws configure

```

Enter:

- AWS Access Key ID
- AWS Secret Access Key
- Default region: `us-west-2`
- Default output format: `json`

---

## Database Setup

### Step 4: Create the Questions Table

```bash
bash
Copy
# Create a file for the questions table creation
cat > create-questions-table.sh << 'EOF'
#!/bin/bash
aws dynamodb create-table \
    --table-name PTE_Questions \
    --attribute-definitions AttributeName=questionId,AttributeType=S \
    --key-schema AttributeName=questionId,KeyType=HASH \
    --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 \
    --region us-west-2
EOF

# Make it executable
chmod +x create-questions-table.sh

# Run it
./create-questions-table.sh

# Verify the table was created
aws dynamodb describe-table --table-name PTE_Questions

```

### Step 5: Create the User Progress Table

```bash
bash
Copy
# Create a file for the user progress table creation
cat > create-user-progress-table.sh << 'EOF'
#!/bin/bash
aws dynamodb create-table \
    --table-name PTE_UserProgress \
    --attribute-definitions \
        AttributeName=userId,AttributeType=S \
        AttributeName=questionId,AttributeType=S \
    --key-schema \
        AttributeName=userId,KeyType=HASH \
        AttributeName=questionId,KeyType=RANGE \
    --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 \
    --region us-west-2
EOF

# Make it executable
chmod +x create-user-progress-table.sh

# Run it
./create-user-progress-table.sh

# Verify the table was created
aws dynamodb describe-table --table-name PTE_UserProgress

```

### Step 6: Add Sample Questions

```bash
bash
Copy
# Create a script to add sample questions
cat > add-sample-questions.sh << 'EOF'
#!/bin/bash

# Question 1 - Vocabulary
aws dynamodb put-item \
    --table-name PTE_Questions \
    --item '{
        "questionId": {"S": "q001"},
        "questionType": {"S": "Vocabulary"},
        "questionText": {"S": "Select the word that is most similar in meaning to \"articulate\"."},
        "options": {"M": {
            "A": {"S": "Incoherent"},
            "B": {"S": "Eloquent"},
            "C": {"S": "Taciturn"},
            "D": {"S": "Random"}
        }},
        "correctAnswer": {"S": "B"}
    }' \
    --region us-west-2

# Question 2 - Grammar
aws dynamodb put-item \
    --table-name PTE_Questions \
    --item '{
        "questionId": {"S": "q002"},
        "questionType": {"S": "Grammar"},
        "questionText": {"S": "Identify the sentence that is grammatically correct:"},
        "options": {"M": {
            "A": {"S": "He don't like reading books."},
            "B": {"S": "She have been working since morning."},
            "C": {"S": "They is going to the concert tonight."},
            "D": {"S": "We are planning to visit the museum tomorrow."}
        }},
        "correctAnswer": {"S": "D"}
    }' \
    --region us-west-2
EOF

# Make it executable
chmod +x add-sample-questions.sh

# Run it
./add-sample-questions.sh

# Verify questions were added
aws dynamodb scan --table-name PTE_Questions

```

### Step 7: Add Secondary Index for Question Queries

```bash
bash
Copy
# Add Global Secondary Index to the User Progress table
aws dynamodb update-table \
    --table-name PTE_UserProgress \
    --attribute-definitions AttributeName=questionId,AttributeType=S \
    --global-secondary-indexes \
        "[{\"IndexName\": \"QuestionIdIndex\",\"KeySchema\": [{\"AttributeName\":\"questionId\",\"KeyType\":\"HASH\"}],\"Projection\":{\"ProjectionType\":\"ALL\"},\"ProvisionedThroughput\":{\"ReadCapacityUnits\":5,\"WriteCapacityUnits\":5}}]" \
    --region us-west-2

```

---

## IAM Setup

### Step 8: Create IAM Role for Lambda

```bash
bash
Copy
# Create a Trust Policy file
cat > trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "lambda.amazonaws.com" },
    "Action": "sts:AssumeRole"
  }]
}
EOF

# Create the role
aws iam create-role \
    --role-name LambdaDynamoDBRole \
    --assume-role-policy-document file://trust-policy.json

# Attach required policies
aws iam attach-role-policy \
    --role-name LambdaDynamoDBRole \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

aws iam attach-role-policy \
    --role-name LambdaDynamoDBRole \
    --policy-arn arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess

# Get and save the role ARN
LAMBDA_ROLE_ARN=$(aws iam get-role --role-name LambdaDynamoDBRole --query 'Role.Arn' --output text)
echo "Lambda Role ARN: $LAMBDA_ROLE_ARN"
echo "export LAMBDA_ROLE_ARN=$LAMBDA_ROLE_ARN" >> ~/.bashrc
source ~/.bashrc

```

---

## Lambda Function Setup

### Step 9: Create Lambda Function Code

```bash
bash
Copy
# Create a directory for your Lambda function
mkdir -p ~/pte-app/lambda-function
cd ~/pte-app/lambda-function

# Initialize a Node.js project
npm init -y

# Install AWS SDK and UUID
npm install aws-sdk uuid

```

Create `index.js` for the Lambda function:

```bash
bash
Copy
# Create index.js file with all handler functions
cat > index.js << 'EOF'
const AWS = require('aws-sdk');
AWS.config.update({ region: 'us-west-2' });
const dynamoDb = new AWS.DynamoDB.DocumentClient();
const uuid = require('uuid');

exports.handler = async (event) => {
    console.log('Event:', JSON.stringify(event, null, 2));

    // Get the user ID and group from the AppSync context
    const userId = event.identity ? event.identity.username || event.identity.sub : null;
    const userGroups = event.identity && event.identity.claims && event.identity.claims['cognito:groups']
        ? event.identity.claims['cognito:groups']
        : [];
    const isAdmin = userGroups.includes('Admins');

    const { field } = event;
    const args = event.arguments || {};

    // Route to the appropriate handler based on the field
    switch(field) {
        // Query operations
        case 'getQuestion':
            return await getQuestion(args.questionId);
        case 'listQuestions':
            return await listQuestions();
        case 'getUserProgress':
            if (!userId) throw new Error('Authentication required');
            return await getUserProgress(userId);
        case 'getAllUserProgress':
            if (!isAdmin) throw new Error('Admin access required');
            return await getAllUserProgress();

        // Mutation operations
        case 'submitAnswer':
            if (!userId) throw new Error('Authentication required');
            return await submitAnswer(userId, args.questionId, args.answer);
        case 'createQuestion':
            if (!isAdmin) throw new Error('Admin access required');
            return await createQuestion(userId, args);
        case 'updateQuestion':
            if (!isAdmin) throw new Error('Admin access required');
            return await updateQuestion(args);
        case 'deleteQuestion':
            if (!isAdmin) throw new Error('Admin access required');
            return await deleteQuestion(args.questionId);
        default:
            throw new Error(`Unknown field: ${field}`);
    }
};

// Query Handlers
async function getQuestion(questionId) {
    const params = {
        TableName: 'PTE_Questions',
        Key: { questionId }
    };
    try {
        const data = await dynamoDb.get(params).promise();
        return data.Item;
    } catch (error) {
        console.error('Error fetching question:', error);
        throw new Error('Could not fetch the question.');
    }
}

async function listQuestions() {
    const params = { TableName: 'PTE_Questions' };
    try {
        const data = await dynamoDb.scan(params).promise();
        return data.Items;
    } catch (error) {
        console.error('Error scanning questions:', error);
        throw new Error('Could not fetch questions.');
    }
}

async function getUserProgress(userId) {
    const params = {
        TableName: 'PTE_UserProgress',
        KeyConditionExpression: 'userId = :userId',
        ExpressionAttributeValues: {
            ':userId': userId
        }
    };
    try {
        const data = await dynamoDb.query(params).promise();
        return data.Items;
    } catch (error) {
        console.error('Error fetching user progress:', error);
        throw new Error('Could not fetch user progress.');
    }
}

async function getAllUserProgress() {
    const params = { TableName: 'PTE_UserProgress' };
    try {
        const data = await dynamoDb.scan(params).promise();
        return data.Items;
    } catch (error) {
        console.error('Error fetching all user progress:', error);
        throw new Error('Could not fetch all user progress.');
    }
}

// Mutation Handlers
async function submitAnswer(userId, questionId, answer) {
    // Fetch the question to check the correct answer
    const question = await getQuestion(questionId);
    const isCorrect = question && question.correctAnswer === answer;

    // Update user progress
    await updateUserProgress(userId, questionId, true, isCorrect);

    return isCorrect;
}

async function updateUserProgress(userId, questionId, completed, correct) {
    const timestamp = new Date().toISOString();
    const params = {
        TableName: 'PTE_UserProgress',
        Item: {
            userId,
            questionId,
            completed,
            correct,
            timestamp
        }
    };
    try {
        await dynamoDb.put(params).promise();
        return params.Item;
    } catch (error) {
        console.error('Error updating user progress:', error);
        throw new Error('Could not update user progress.');
    }
}

async function createQuestion(createdBy, args) {
    const questionId = args.questionId || uuid.v4();
    const timestamp = new Date().toISOString();

    const item = {
        questionId,
        questionType: args.questionType,
        questionText: args.questionText,
        options: {
            A: args.optionA,
            B: args.optionB,
            C: args.optionC,
            D: args.optionD
        },
        correctAnswer: args.correctAnswer,
        createdBy,
        createdAt: timestamp,
        updatedAt: timestamp
    };

    const params = {
        TableName: 'PTE_Questions',
        Item: item
    };

    try {
        await dynamoDb.put(params).promise();
        return item;
    } catch (error) {
        console.error('Error creating question:', error);
        throw new Error('Could not create question.');
    }
}

async function updateQuestion(args) {
    // First check if the question exists
    const question = await getQuestion(args.questionId);
    if (!question) {
        throw new Error('Question not found');
    }

    // Prepare update expression and attribute values
    let updateExpression = 'SET updatedAt = :updatedAt';
    const expressionAttributeValues = {
        ':updatedAt': new Date().toISOString()
    };

    // Add optional fields to update if they are provided
    if (args.questionType) {
        updateExpression += ', questionType = :questionType';
        expressionAttributeValues[':questionType'] = args.questionType;
    }

    if (args.questionText) {
        updateExpression += ', questionText = :questionText';
        expressionAttributeValues[':questionText'] = args.questionText;
    }

    if (args.optionA || args.optionB || args.optionC || args.optionD) {
        // For options, we need to merge with existing options
        const updatedOptions = {
            ...(question.options || {}),
            ...(args.optionA && { A: args.optionA }),
            ...(args.optionB && { B: args.optionB }),
            ...(args.optionC && { C: args.optionC }),
            ...(args.optionD && { D: args.optionD })
        };

        updateExpression += ', options = :options';
        expressionAttributeValues[':options'] = updatedOptions;
    }

    if (args.correctAnswer) {
        updateExpression += ', correctAnswer = :correctAnswer';
        expressionAttributeValues[':correctAnswer'] = args.correctAnswer;
    }

    const params = {
        TableName: 'PTE_Questions',
        Key: { questionId: args.questionId },
        UpdateExpression: updateExpression,
        ExpressionAttributeValues: expressionAttributeValues,
        ReturnValues: 'ALL_NEW'
    };

    try {
        const result = await dynamoDb.update(params).promise();
        return result.Attributes;
    } catch (error) {
        console.error('Error updating question:', error);
        throw new Error('Could not update question.');
    }
}

async function deleteQuestion(questionId) {
    // First check if the question exists
    const question = await getQuestion(questionId);
    if (!question) {
        throw new Error('Question not found');
    }

    const params = {
        TableName: 'PTE_Questions',
        Key: { questionId }
    };

    try {
        await dynamoDb.delete(params).promise();
        return true;
    } catch (error) {
        console.error('Error deleting question:', error);
        throw new Error('Could not delete question.');
    }
}
EOF

```

### Step 10: Deploy the Lambda Function

```bash
bash
Copy
# Zip the Lambda function
zip -r function.zip index.js node_modules

# Deploy the Lambda function
aws lambda create-function \
    --function-name PTEQuestionsFunction \
    --runtime nodejs14.x \
    --role $LAMBDA_ROLE_ARN \
    --handler index.handler \
    --zip-file fileb://function.zip \
    --region us-west-2

# Save the Lambda ARN
LAMBDA_ARN=$(aws lambda get-function --function-name PTEQuestionsFunction --query 'Configuration.FunctionArn' --output text)
echo "Lambda ARN: $LAMBDA_ARN"
echo "export LAMBDA_ARN=$LAMBDA_ARN" >> ~/.bashrc
source ~/.bashrc

```

---

## Cognito User Authentication Setup

### Step 11: Create Cognito User Pool

```bash
bash
Copy
# Create the user pool
aws cognito-idp create-user-pool \
    --pool-name PTE-User-Pool \
    --auto-verify-attributes email \
    --schema Name=email,Required=true,Mutable=true \
    --username-attributes email \
    --policies '{"PasswordPolicy":{"MinimumLength":8,"RequireUppercase":true,"RequireLowercase":true,"RequireNumbers":true,"RequireSymbols":true}}' \
    --region us-west-2 > user-pool-output.json

# Extract and save the User Pool ID
USER_POOL_ID=$(cat user-pool-output.json | grep -o '"Id": "[^"]*"' | cut -d'"' -f4)
echo "User Pool ID: $USER_POOL_ID"
echo "export USER_POOL_ID=$USER_POOL_ID" >> ~/.bashrc

```

### Step 12: Create User Groups

```bash
bash
Copy
# Create admin group
aws cognito-idp create-group \
    --user-pool-id $USER_POOL_ID \
    --group-name Admins \
    --description "Administrators who can manage questions" \
    --region us-west-2

# Create users group
aws cognito-idp create-group \
    --user-pool-id $USER_POOL_ID \
    --group-name Users \
    --description "Regular users who can take tests" \
    --region us-west-2

```

### Step 13: Create App Client

```bash
bash
Copy
# Create an app client
aws cognito-idp create-user-pool-client \
    --user-pool-id $USER_POOL_ID \
    --client-name PTE-App-Client \
    --no-generate-secret \
    --explicit-auth-flows ADMIN_NO_SRP_AUTH USER_PASSWORD_AUTH \
    --region us-west-2 > app-client-output.json

# Extract and save the App Client ID
APP_CLIENT_ID=$(cat app-client-output.json | grep -o '"ClientId": "[^"]*"' | cut -d'"' -f4)
echo "App Client ID: $APP_CLIENT_ID"
echo "export APP_CLIENT_ID=$APP_CLIENT_ID" >> ~/.bashrc
source ~/.bashrc

```

### Step 14: Create Test Users

```bash
bash
Copy
# Create admin user
aws cognito-idp admin-create-user \
    --user-pool-id $USER_POOL_ID \
    --username admin@example.com \
    --temporary-password Admin@123 \
    --user-attributes Name=email,Value=admin@example.com \
    --region us-west-2

# Set permanent password for admin
aws cognito-idp admin-set-user-password \
    --user-pool-id $USER_POOL_ID \
    --username admin@example.com \
    --password AdminSecurePass123! \
    --permanent \
    --region us-west-2

# Add admin to Admins group
aws cognito-idp admin-add-user-to-group \
    --user-pool-id $USER_POOL_ID \
    --username admin@example.com \
    --group-name Admins \
    --region us-west-2

# Create regular user
aws cognito-idp admin-create-user \
    --user-pool-id $USER_POOL_ID \
    --username user@example.com \
    --temporary-password User@123 \
    --user-attributes Name=email,Value=user@example.com \
    --region us-west-2

# Set permanent password for regular user
aws cognito-idp admin-set-user-password \
    --user-pool-id $USER_POOL_ID \
    --username user@example.com \
    --password UserSecurePass123! \
    --permanent \
    --region us-west-2

# Add user to Users group
aws cognito-idp admin-add-user-to-group \
    --user-pool-id $USER_POOL_ID \
    --username user@example.com \
    --group-name Users \
    --region us-west-2

```

### Step 15: Set Up Identity Pool

```bash
bash
Copy
# Create an identity pool
aws cognito-identity create-identity-pool \
    --identity-pool-name PTE-Identity-Pool \
    --allow-unauthenticated-identities false \
    --cognito-identity-providers ProviderName=cognito-idp.us-west-2.amazonaws.com/$USER_POOL_ID,ClientId=$APP_CLIENT_ID,ServerSideTokenCheck=true \
    --region us-west-2 > identity-pool-output.json

# Extract and save the Identity Pool ID
IDENTITY_POOL_ID=$(cat identity-pool-output.json | grep -o '"IdentityPoolId": "[^"]*"' | cut -d'"' -f4)
echo "Identity Pool ID: $IDENTITY_POOL_ID"
echo "export IDENTITY_POOL_ID=$IDENTITY_POOL_ID" >> ~/.bashrc
source ~/.bashrc

```

### Step 16: Set Up IAM Roles for Identity Pool

```bash
bash
Copy
# Get your AWS account ID
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
echo "AWS Account ID: $AWS_ACCOUNT_ID"
echo "export AWS_ACCOUNT_ID=$AWS_ACCOUNT_ID" >> ~/.bashrc

# Create IAM roles for authenticated users
cat > auth-role-trust-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "cognito-identity.amazonaws.com"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "cognito-identity.amazonaws.com:aud": "$IDENTITY_POOL_ID"
                },
                "ForAnyValue:StringLike": {
                    "cognito-identity.amazonaws.com:amr": "authenticated"
                }
            }
        }
    ]
}
EOF

aws iam create-role \
    --role-name PTE-Cognito-Authenticated \
    --assume-role-policy-document file://auth-role-trust-policy.json

# Add basic permissions
cat > auth-role-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cognito-sync:*",
                "cognito-identity:*"
            ],
            "Resource": "*"
        }
    ]
}
EOF

aws iam put-role-policy \
    --role-name PTE-Cognito-Authenticated \
    --policy-name CognitoAuthenticatedPolicy \
    --policy-document file://auth-role-policy.json

# Get and save the role ARN
AUTH_ROLE_ARN=$(aws iam get-role --role-name PTE-Cognito-Authenticated --query 'Role.Arn' --output text)
echo "Auth Role ARN: $AUTH_ROLE_ARN"
echo "export AUTH_ROLE_ARN=$AUTH_ROLE_ARN" >> ~/.bashrc

# Link the roles to your Identity Pool
aws cognito-identity set-identity-pool-roles \
    --identity-pool-id $IDENTITY_POOL_ID \
    --roles authenticated=$AUTH_ROLE_ARN \
    --region us-west-2

```

### Step 17: Test Authentication

```bash
bash
Copy
# Get admin token
aws cognito-idp admin-initiate-auth \
    --user-pool-id $USER_POOL_ID \
    --client-id $APP_CLIENT_ID \
    --auth-flow ADMIN_USER_PASSWORD_AUTH \
    --auth-parameters USERNAME=admin@example.com,PASSWORD=AdminSecurePass123! \
    --region us-west-2 > admin-auth-output.json

# Extract and save the Admin token
ADMIN_TOKEN=$(cat admin-auth-output.json | grep -o '"IdToken": "[^"]*"' | cut -d'"' -f4)
echo "Admin Token: $ADMIN_TOKEN"
echo "export ADMIN_TOKEN=$ADMIN_TOKEN" >> ~/.bashrc

# Get user token
aws cognito-idp admin-initiate-auth \
    --user-pool-id $USER_POOL_ID \
    --client-id $APP_CLIENT_ID \
    --auth-flow ADMIN_USER_PASSWORD_AUTH \
    --auth-parameters USERNAME=user@example.com,PASSWORD=UserSecurePass123! \
    --region us-west-2 > user-auth-output.json

# Extract and save the User token
USER_TOKEN=$(cat user-auth-output.json | grep -o '"IdToken": "[^"]*"' | cut -d'"' -f4)
echo "User Token: $USER_TOKEN"
echo "export USER_TOKEN=$USER_TOKEN" >> ~/.bashrc
source ~/.bashrc

```

---

## AppSync GraphQL API Setup

### Step 18: Create the AppSync API

```bash
bash
Copy
# Create the AppSync API with Cognito User Pool authentication
aws appsync create-graphql-api \
    --name PTE-GraphQL-API \
    --authentication-type AMAZON_COGNITO_USER_POOLS \
    --user-pool-config userPoolId=$USER_POOL_ID,awsRegion=us-west-2,defaultAction=ALLOW \
    --region us-west-2 > appsync-output.json

# Extract and save the API ID
API_ID=$(cat appsync-output.json | grep -o '"apiId": "[^"]*"' | cut -d'"' -f4)
echo "AppSync API ID: $API_ID"
echo "export API_ID=$API_ID" >> ~/.bashrc
source ~/.bashrc

```

### Step 19: Create GraphQL Schema

```bash
# Create the schema file as before
cat > schema.graphql << 'EOF'
directive @auth(roles: [String]) on FIELD_DEFINITION

type Options {
  A: String
  B: String
  C: String
  D: String
}

type Question {
  questionId: ID!
  questionType: String
  questionText: String
  options: Options
  correctAnswer: String
  createdBy: String
  createdAt: String
  updatedAt: String
}

type UserProgress {
  userId: ID!
  questionId: ID!
  completed: Boolean
  correct: Boolean
  timestamp: String
}

type Query {
  # User operations
  getQuestion(questionId: ID!): Question @auth(roles: ["Users", "Admins"])
  listQuestions: [Question] @auth(roles: ["Users", "Admins"])
  getUserProgress: [UserProgress] @auth(roles: ["Users", "Admins"])
  
  # Admin operations
  getAllUserProgress: [UserProgress] @auth(roles: ["Admins"])
}

type Mutation {
  # User operations
  submitAnswer(questionId: ID!, answer: String!): Boolean @auth(roles: ["Users", "Admins"])
  
  # Admin operations
  createQuestion(
    questionType: String!, 
    questionText: String!, 
    optionA: String!,
    optionB: String!,
    optionC: String!,
    optionD: String!,
    correctAnswer: String!
  ): Question @auth(roles: ["Admins"])
  
  updateQuestion(
    questionId: ID!,
    questionType: String, 
    questionText: String, 
    optionA: String,
    optionB: String,
    optionC: String,
    optionD: String,
    correctAnswer: String
  ): Question @auth(roles: ["Admins"])
  
  deleteQuestion(questionId: ID!): Boolean @auth(roles: ["Admins"])
}

schema {
  query: Query
  mutation: Mutation
}
EOF

# Properly base64 encode the schema - the key fix is here
SCHEMA_BASE64=$(base64 -w 0 schema.graphql)

# Upload schema to AppSync
aws appsync start-schema-creation \
    --api-id $API_ID \
    --definition file://schema.graphql \
    --region us-west-2
```

### Step 20: Create AppSync Data Source for Lambda

```bash

# Create IAM role for AppSync to invoke Lambda
cat > appsync-role-trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "appsync.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

aws iam create-role \
    --role-name AppSyncLambdaRole \
    --assume-role-policy-document file://appsync-role-trust-policy.json

# Attach Lambda Invoke policy
cat > lambda-invoke-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "lambda:InvokeFunction"
      ],
      "Resource": [
        "$LAMBDA_ARN"
      ]
    }
  ]
}
EOF

aws iam put-role-policy \
    --role-name AppSyncLambdaRole \
    --policy-name AppSyncLambdaInvokePolicy \
    --policy-document file://lambda-invoke-policy.json

# Get the AppSync Role ARN
APPSYNC_ROLE_ARN=$(aws iam get-role --role-name AppSyncLambdaRole --query 'Role.Arn' --output text)
echo "AppSync Role ARN: $APPSYNC_ROLE_ARN"
echo "export APPSYNC_ROLE_ARN=$APPSYNC_ROLE_ARN" >> ~/.bashrc
source ~/.bashrc

# Create the data source
aws appsync create-data-source \
    --api-id $API_ID \
    --name PTELambdaDataSource \
    --type AWS_LAMBDA \
    --lambda-config lambdaFunctionArn=$LAMBDA_ARN \
    --service-role-arn $APPSYNC_ROLE_ARN \
    --region us-west-2

```

### Step 21: Create Resolver Templates and Resolvers

```bash
# Create request mapping template
cat > request-template.vtl << 'EOF'
{
  "version": "2017-02-28",
  "operation": "Invoke",
  "payload": {
    "field": "$context.info.fieldName",
    "arguments": $util.toJson($context.arguments),
    "identity": $util.toJson($context.identity)
  }
}
EOF

# Create response mapping template
cat > response-template.vtl << 'EOF'
$util.toJson($context.result)
EOF

# Create resolvers for queries
# Create getQuestion resolver
aws appsync create-resolver \
    --api-id $API_ID \
    --type-name Query \
    --field-name getQuestion \
    --data-source-name PTELambdaDataSource \
    --request-mapping-template file://request-template.vtl \
    --response-mapping-template file://response-template.vtl \
    --region us-west-2

# Create listQuestions resolver
aws appsync create-resolver \
    --api-id $API_ID \
    --type-name Query \
    --field-name listQuestions \
    --data-source-name PTELambdaDataSource \
    --request-mapping-template file://request-template.vtl \
    --response-mapping-template file://response-template.vtl \
    --region us-west-2

# Create getUserProgress resolver
aws appsync create-resolver \
    --api-id $API_ID \
    --type-name Query \
    --field-name getUserProgress \
    --data-source-name PTELambdaDataSource \
    --request-mapping-template file://request-template.vtl \
    --response-mapping-template file://response-template.vtl \
    --region us-west-2

# Create getAllUserProgress resolver (admin only)
aws appsync create-resolver \
    --api-id $API_ID \
    --type-name Query \
    --field-name getAllUserProgress \
    --data-source-name PTELambdaDataSource \
    --request-mapping-template file://request-template.vtl \
    --response-mapping-template file://response-template.vtl \
    --region us-west-2

# Create resolvers for mutations
# Create submitAnswer resolver
aws appsync create-resolver \
    --api-id $API_ID \
    --type-name Mutation \
    --field-name submitAnswer \
    --data-source-name PTELambdaDataSource \
    --request-mapping-template file://request-template.vtl \
    --response-mapping-template file://response-template.vtl \
    --region us-west-2

# Create createQuestion resolver (admin only)
aws appsync create-resolver \
    --api-id $API_ID \
    --type-name Mutation \
    --field-name createQuestion \
    --data-source-name PTELambdaDataSource \
    --request-mapping-template file://request-template.vtl \
    --response-mapping-template file://response-template.vtl \
    --region us-west-2

# Create updateQuestion resolver (admin only)
aws appsync create-resolver \
    --api-id $API_ID \
    --type-name Mutation \
    --field-name updateQuestion \
    --data-source-name PTELambdaDataSource \
    --request-mapping-template file://request-template.vtl \
    --response-mapping-template file://response-template.vtl \
    --region us-west-2

# Create deleteQuestion resolver (admin only)
aws appsync create-resolver \
    --api-id $API_ID \
    --type-name Mutation \
    --field-name deleteQuestion \
    --data-source-name PTELambdaDataSource \
    --request-mapping-template file://request-template.vtl \
    --response-mapping-template file://response-template.vtl \
    --region us-west-2
```

---

## Testing the Complete API

### Step 22: Get Your GraphQL API URL

```bash

# Get the API URL
API_URL=$(aws appsync get-graphql-api --api-id $API_ID --region us-west-2 --query 'graphqlApi.uris.GRAPHQL' --output text)
echo "GraphQL API URL: $API_URL"
echo "export API_URL=$API_URL" >> ~/.bashrc
source ~/.bashrc

```

### Step 23: Test Admin Operations

```bash

# Create a test question using admin token
cat > create-question-test.json << EOF
{
  "query": "mutation CreateQuestion { createQuestion(questionType: \"Listening\", questionText: \"Select the word that matches what you hear:\", optionA: \"Receive\", optionB: \"Recieve\", optionC: \"Relieve\", optionD: \"Retrieve\", correctAnswer: \"A\") { questionId questionType questionText } }"
}
EOF

# Send the request using curl
curl -X POST $API_URL \
  -H "Content-Type: application/json" \
  -H "Authorization: $ADMIN_TOKEN" \
  -d @create-question-test.json

# List all questions as admin
cat > list-questions-test.json << EOF
{
  "query": "query ListQuestions { listQuestions { questionId questionType questionText options { A B C D } correctAnswer } }"
}
EOF

curl -X POST $API_URL \
  -H "Content-Type: application/json" \
  -H "Authorization: $ADMIN_TOKEN" \
  -d @list-questions-test.json

```

### Step 24: Test Regular User Operations

```bash
bash
Copy
# List questions as regular user
curl -X POST $API_URL \
  -H "Content-Type: application/json" \
  -H "Authorization: $USER_TOKEN" \
  -d @list-questions-test.json

# Submit an answer as regular user (replace QUESTION_ID with an actual question ID from the previous response)
cat > submit-answer-test.json << EOF
{
  "query": "mutation SubmitAnswer { submitAnswer(questionId: \"QUESTION_ID\", answer: \"A\") }"
}
EOF

curl -X POST $API_URL \
  -H "Content-Type: application/json" \
  -H "Authorization: $USER_TOKEN" \
  -d @submit-answer-test.json

# Get user progress
cat > get-progress-test.json << EOF
{
  "query": "query GetUserProgress { getUserProgress { questionId completed correct timestamp } }"
}
EOF

curl -X POST $API_URL \
  -H "Content-Type: application/json" \
  -H "Authorization: $USER_TOKEN" \
  -d @get-progress-test.json

```

### Step 25: Test Admin-Only Operations

```bash
bash
Copy
# Get all user progress (admin only)
cat > get-all-progress-test.json << EOF
{
  "query": "query GetAllUserProgress { getAllUserProgress { userId questionId completed correct timestamp } }"
}
EOF

# This should succeed with admin token
curl -X POST $API_URL \
  -H "Content-Type: application/json" \
  -H "Authorization: $ADMIN_TOKEN" \
  -d @get-all-progress-test.json

# This should fail with regular user token
curl -X POST $API_URL \
  -H "Content-Type: application/json" \
  -H "Authorization: $USER_TOKEN" \
  -d @get-all-progress-test.json

```

---

## Security Enhancements

### Step 26: Add CloudWatch Logging

```bash
bash
Copy
# Enable CloudWatch logging for AppSync
aws appsync update-graphql-api \
    --api-id $API_ID \
    --name PTE-GraphQL-API \
    --log-config fieldLogLevel=ERROR \
    --region us-west-2

```

### Step 27: Configure Token Expiration

```bash
bash
Copy
# Set token expiration settings
aws cognito-idp update-user-pool-client \
    --user-pool-id $USER_POOL_ID \
    --client-id $APP_CLIENT_ID \
    --refresh-token-validity 30 \
    --access-token-validity 1 \
    --id-token-validity 1 \
    --token-validity-units "AccessToken=hours,IdToken=hours,RefreshToken=days" \
    --region us-west-2

```

### Step 28: Enable MFA (Optional)

```bash
bash
Copy
# Enable optional MFA for the user pool
aws cognito-idp set-user-pool-mfa-config \
    --user-pool-id $USER_POOL_ID \
    --software-token-mfa-configuration Enabled=true \
    --mfa-configuration OPTIONAL \
    --region us-west-2

```

---

## Clean-Up Script (Optional)

Create a cleanup script for when you want to tear down the resources:

```bash
bash
Copy
# Create cleanup script
cat > cleanup.sh << 'EOF'
#!/bin/bash

# Delete AppSync API
aws appsync delete-graphql-api --api-id $API_ID --region us-west-2

# Delete Lambda function
aws lambda delete-function --function-name PTEQuestionsFunction --region us-west-2

# Delete Cognito Identity Pool
aws cognito-identity delete-identity-pool --identity-pool-id $IDENTITY_POOL_ID --region us-west-2

# Delete Cognito User Pool
aws cognito-idp delete-user-pool --user-pool-id $USER_POOL_ID --region us-west-2

# Delete DynamoDB tables
aws dynamodb delete-table --table-name PTE_Questions --region us-west-2
aws dynamodb delete-table --table-name PTE_UserProgress --region us-west-2

# Detach and delete IAM policies and roles
aws iam detach-role-policy --role-name LambdaDynamoDBRole --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
aws iam detach-role-policy --role-name LambdaDynamoDBRole --policy-arn arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess
aws iam delete-role --role-name LambdaDynamoDBRole

aws iam delete-role-policy --role-name AppSyncLambdaRole --policy-name AppSyncLambdaInvokePolicy
aws iam delete-role --role-name AppSyncLambdaRole

aws iam delete-role-policy --role-name PTE-Cognito-Authenticated --policy-name CognitoAuthenticatedPolicy
aws iam delete-role --role-name PTE-Cognito-Authenticated

echo "All PTE application resources have been deleted."
EOF

chmod +x cleanup.sh

```

---

## Conclusion

This documentation provides a complete guide to deploying a serverless PTE Questions application on AWS with role-based authentication. The architecture includes:

1. **DynamoDB tables** for storing questions and user progress
2. **Lambda functions** for business logic and data access
3. **Cognito User Pools** for authentication with admin and regular user roles
4. **AppSync GraphQL API** for client access with role-based permissions

The setup allows:

- Administrators to create, update, and delete questions and view all user progress
- Regular users to view questions, submit answers, and track their own progress

The system is fully serverless, scalable, and secure with proper authentication and authorization controls.
