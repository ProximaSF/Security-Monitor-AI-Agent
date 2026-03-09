# AWS Lambda Function & S3 (Simple Storage Service)

## About:

The purpose of this markdown document is to setup a lambda function to build upon the CloudWatch Agent setup. The reason I made a lambda function is so I can automate system log event messages with a single script instead of manually reading the logs inside the instance to check for suspicious activity. As for S3, I happen to use this service because the zip file for the python dependencies was more than 10MB - plus, I wanted to see how S3 work and its purpose so I can use it later for the full AI agent integration with Bedrock.  

So far I only have one script to handle `auth-logs`. The script language I am for the function is Python version 3.14. So please make sure the zip file (`python.zip`) dependencies is for v3.14 or greater, or else it might not work. More instruction in Process section.



## Process:

### 1. Create a S3 bucket to store

- Pick a name. Use hyphen in place of space
- The region of the bucket need to be the same for the lambda function

### 2. Create lambda function

1. Create a new IAM role so the function can read files from CloudWatch
   - Call the role something like `lambda-threat-detector-policy`
   - Add `AmazonSNSFullAccess `& `CloudWatchLogsFullAccess` for Permission Policy

2. Pick "Author from scratch" or a blueprint
   - Using the provided script, pick the first option
3. Will be using Python for Runtime
4. under "Change default execution role," add the newly created role
5. Name the function something like `threat-detector`
6. Click "Create function"

### 3. Adding Code to Function

1. Click on the "Code" tab
2. Past the code from `threat_detector.py` and replace example code for the function.
   - Depending on the complexity of the script, might need to increase "timeout" value so the function can fully execute before AWS force stop the function 
     - Configuration → Edit → Timeout → adjust value if needed
3. Click Deploy to update code

### 4. Add Layer for Dependences

#### Option 1: Upload Zip Dependencies

##### 1. Create zip dependencies:

1. Create a folder or using the clone repository, create a .venv and activate inside the folder

   ```bash
   python -m venv .venv
   .venv/Scripts/activate # Powershell
   source ".venv/bin/activate" # Bash
   ```

2. Pip install all required dependence

   ```bash
   pip install -r ./requirements.txt
   ```

3. Create folder called `python`

4. Copy and past all file from `.venv/Lib/site-packages` to the new created folder `python`

5. Zip the folder

   - <u>If the file is more than 10MB, create a S3 bucket and store the zip file in there instead</u>

##### 2. Create Lambda Layer to Attach Zip File:

1. On AWS Console on Lambda Function service, in "Additional resource" on the left, click on layer → create layer
2. Name the layer something like `threat-detection-lambda-layer-dependences` 
3. upload the `site-packages` zip file with the dependences

   - <u>For S3, grab the URL for the .zip link inside the bucket and past it in the "Amazon S3 link URL" field</u>
4. Select arm64 (cheaper and something)
5. Pick Python 3.14 or whichever version the lambda function is using
6. click create

##### 3. Create Layer for Function to use Zip File:

1. Go back to the lambda function: `threat-detector`
2. Scroll to the bottom and click "Add a layer"

   - The function will use this layer to call and use the lambda layer that contain the zip dependences
3. Select "Custom layers" and select the lambda layer: `threat-detection-layer-dependences`
4. Select version 
5. Click "Add"

##### 4. Add Environment Variable for Function

1. Inside the Lambda function with the code, click on "Configuration"

2. Select "Environment variables"

3. Click edit → Add Environment Variable 

4. Add the Discord Webhook URL as value

   - Make sure the key matches the one used in the script

     

## Learning Curves:

Using AWS Lambda Function and S3 service was rather surprisingly easy to use. Regardless, I provided some issues I faced and what I've learned during the setup below.  

- One main obstacle I faced was understanding the two different layers (lambda and function). 

  - The lambda layer stores files like dependences that lives outside the function code. The main purpose is so it can be reusable resource to attach to multiple functions. 
  - The layer inside the function is so it can use the lambda layer to properly run the function script.

- For lambda function, AWS have a built-in environment variable. Do not need to import dotenv and os. This means making a `.env` file is not required. 

  ```python
  # With .env file and import python-dotenv
  WEBHOOK_URL = os.getenv("WEBHOOK_URL") 
  
  # For AWS Lambda Function
  WEBHOOK_URL = os.environ.get("WEBHOOK_URL")
  ```

- When zipping python folder with dependences, only add dependences that is used in the code or else it might not work. 



