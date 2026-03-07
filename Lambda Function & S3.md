# AWS Lambda Function & S3 (Simple Storage Service)

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

##### 2. Create Global Layer to Attach Zip File:

1. On AWS Console on Lambda Function service, in "Additional resource" on the left, click on layer → create layer
2. Name the layer something like `threat-detection-layer-dependences` 
3. upload the `site-packages` zip file with the dependences

   - <u>For S3, grab the URL for the .zip link inside the bucket and past it in the "Amazon S3 link URL" field</u>
4. Select arm64 (cheaper and something)
5. Pick Python 3.14 or whichever version the lambda function is using
6. click create

##### 3. Create Function Layer to use Zip File:

1. Go back to the lambda function: `threat-detector`

2. Scroll to the bottom and click "Add a layer"

   - The function will use this layer to call and use the global layer with the dependences

3. Select "Custom layers" and select the global layer: `threat-detection-layer-dependences`

4. Select version 

5. Click "Add"









