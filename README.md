# AWS EC2 CloudWatch Agent

## Objective:

The goal of this "activity" is to experiment and understand how AWS CloudWatch, lambda Function and S3 work. The end goal of this is to create a AI agent for security purpose (read system logs, file, etc). 

There are 3 other markdown file:

1.  [CloudWatch](CloudWatch.md): Documentation how I setup CloudWatch on Ubuntu and AWS console
2.  [WizardSetup](WizardSetup.md): Table showing the options I chose when setting up CloudWatch Agent
3. [Lambda Function & S3](Lambda Function & S3.md): Documentation how I setup Lambda Function and S3 to work with CloudWatch

 
Note: The instance image I used is Ubuntu. Thus, the process of installing AWS CLI or the CloudWatch agent is a bit different: requires downloading a package first (.deb). Additionally, instead of `yum`, it's `apt` to install packages.  

