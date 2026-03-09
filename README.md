# AWS EC2 CloudWatch Agent

## Objective:

The goal of this project is to experiment and understand AWS CloudWatch, lambda Function and S3. The main objective is to create a AI agent for security purpose in mind using Bedrock and the services I've learned. <u>CloudWatch</u> is a AWS service that collects monitoring data from servers/apps. There are 4 services it provides: Logs (text output from applications/systems), metrics (numerical data (CPU %, disk usage, request counts)), events (alerts/triggers (when something happens)) and dashboards, a visual monitoring. <u>Lambda Function</u> is a serverless compute that runs script/code when triggered by a event and stops automatically. And <u>S3 (Simple Storage Service)</u> is a bucket that is a container that stores files. Each bucket have unique names, can hold many-many files and files is organized by keys.

The first thing I started with was experimenting with and learning about CloudWatch Agent. After I set up a log group and stream that connects my EC2 instance to the AWS CloudWatch management console, I then moved on to Lambda functions. This service can trigger a script when a log file updates. The script reads the file and then searches for patterns for security concerns. If a pattern is detected, it calls a Discord webhook and sends a message to the channel. Along the process, I also learned about S3, which I used to store Python dependencies for the script to run. Below, is a diagram to illustrate how each services are connected. Lastly, I have also attached 3 markdown documents for the setup process for each services. 





1.  [CloudWatch](CloudWatch.md): Documentation how I setup CloudWatch on Ubuntu and AWS console
2.  [WizardSetup](WizardSetup.md): Table showing the options I chose when setting up CloudWatch Agent
3.  [Lambda Function & S3](Lambda_Function_&_S3.md): Documentation how I setup Lambda Function and S3 to work with CloudWatch





Note: The instance image I used is Ubuntu. Thus, the process of installing AWS CLI or the CloudWatch agent is a bit different: requires downloading a package first (.deb). Additionally, instead of `yum`, it's `apt` to install packages.  

## Possible Future Improvement Check List

- [ ]  Add more threat detection conditions/logic
- [ ]  Optimize script for AI agent
- [ ]  Store Lambda result to S3 
- [ ] Integrate SSM for convince and security
- [ ] Add more lambda functions for other purpose
- [ ] Provide instruction/process how to install dependences without using S3
- [ ]  Find a job :/

