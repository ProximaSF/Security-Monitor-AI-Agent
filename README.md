# AWS EC2 CloudWatch Agent

## Objective:

This project is to experiment and understand AWS services; CloudWatch, Lambda Function, S3 and Bedrock. The main objective is to create a AI agent for security purpose in mind by monitoring log files and potentially basic actions like blocking IP address.

<u>CloudWatch</u> is a AWS service that collects monitoring data from servers/apps. There are 4 services it provides: Logs (text output from applications/systems), metrics (numerical data (CPU %, disk usage, request counts)), events (alerts/triggers (when something happens)) and dashboards, a visual monitoring. 

<u>Lambda Function</u> is a serverless compute that runs script/code when triggered by a event and stops automatically.

<u>S3 (Simple Storage Service)</u> is a bucket that is a container that stores files. Each bucket have unique names, can hold many-many files and files is organized by keys.

<u>Bedrock</u> is a AWS cloud service that allows the use of foundation models via API to develop applications without managing the AI infrastructure.  

The first thing I started with was experimenting with and learning about CloudWatch Agent. After I set up a log group and stream that connects my EC2 instance to the AWS CloudWatch management console, I then moved on to Lambda functions. This service can trigger a script when a log file updates. The script reads the file and then searches for patterns for security concerns. If a pattern is detected, it calls Bedrock to ask the AI to generate a summary and other information in JSON format, which will be used as a message to send to a Discord channel via a webhook URL. During the process, I also learned about S3, which I used to store Python dependencies for the script to run. Below is a diagram to illustrate how each service is connected. Lastly, I have also attached three Markdown documents for the setup process for each service, besides Bedrock.

<img src="AWS_AI_Agent_Flow.png" alt="AI Agent Flow Diagram" style="width: 400px; height: 300px;">

A diagram to illustrate how the AI Agent is structured using various AWS services as for 3/9/26. 


1. [CloudWatch](CloudWatch.md): Documentation how I setup CloudWatch on Ubuntu and AWS console

2. [WizardSetup](WizardSetup.md): Table showing the options I chose when setting up CloudWatch Agent

3. [Lambda Function & S3](Lambda_Function_&_S3.md): Documentation how I setup Lambda Function and S3 to work with CloudWatch


Note: The instance image I used is Ubuntu. Thus, the process of installing AWS CLI or the CloudWatch agent is a bit different: requires downloading a package first (.deb). Additionally, instead of `yum`, it's `apt` to install packages.  

## Possible Future Improvement Check List

- [x]  Integrate Bedrock for custom AI response
- [x]  Add more threat detection conditions/logic
- [x]  Optimize script for AI agent
- [ ]  Automatically block IP Address after # failed attempts
- [ ]  Store Lambda result to S3 
- [ ] Integrate SSM for convince and security
- [ ] Add more lambda functions for other purpose
- [ ] Provide instruction/process how to install dependences without using S3
- [ ]  Land a job :D

