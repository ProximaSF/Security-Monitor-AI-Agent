import os
import json
import base64
import gzip
import boto3
import inspect
from discord_webhook import DiscordWebhook, DiscordEmbed

WEBHOOK_URL = os.environ.get("WEBHOOK_URL")

# Initialize Bedrock client
bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")


"""Send the detected threat to Bedrock for AI analysis."""
def analyze_with_bedrock(log_message, threat_type, severity):
    
    prompt = f"""You are a cybersecurity AI agent analyzing Linux auth logs.
        A {severity} severity threat was detected: {threat_type}

        Log entry:
        {log_message}

        Respond ONLY in this JSON format, nothing else (do not wrap its response in markdown code fences):
        {{
        "summary": "one sentence explaining what happened",
        "likely_attack": "e.g. brute force, credential stuffing, etc.",
        "recommended_action": "e.g. block IP, monitor, investigate",
        "ip_address": "extract IP from log or null if not found"
        }}"""

    response = bedrock.invoke_model(
        modelId="us.anthropic.claude-sonnet-4-6",
        body=json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 300,
            "messages": [{"role": "user", "content": inspect.cleandoc(prompt)}]
        })
    )

    result = json.loads(response["body"].read())
    raw_text = result["content"][0]["text"]

    # Safely parse the JSON response from Bedrock
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        return {
            "summary": raw_text,
            "likely_attack": "Unknown",
            "recommended_action": "Manual review needed",
            "ip_address": None
        }


def webhook_embed(title, message_description, color=None):
    webhook = DiscordWebhook(url=WEBHOOK_URL)
    embed = DiscordEmbed(
        title=title,
        description=message_description,
        color='03b2f8')
    webhook.add_embed(embed)
    webhook.execute()


def analyze_auth_log(log_message):
    message = log_message.lower()

    threat = {
        'failed_login': {
            'keywords': ['failed password', 'authentication failure'],
            'color': 'orange',
            'severity': 'MEDIUM'
        }
    }

    for threat_type, threat_info in threat.items():
        if any(keyword in message for keyword in threat_info['keywords']):
            return {
                'is_threat': True,
                'type': threat_type,
                'detection': threat_info['keywords'],
                'color': threat_info['color'],
                'severity': threat_info['severity']
            }

    return {'is_threat': False}


def lambda_handler(event, context):
    print("Running...")

    try:
        compressed_data = base64.b64decode(event['awslogs']['data'])
        log_data = json.loads(gzip.decompress(compressed_data))

        log_events = log_data['logEvents']
        log_group = log_data['logGroup']

        suspicious_events = []

        for log_event in log_events:
            message = log_event['message']
            threat_analysis = analyze_auth_log(message)

            if threat_analysis['is_threat']:
                suspicious_events.append({
                    'timestamp': log_event['timestamp'],
                    'message': message,
                    'threat_type': threat_analysis['type'],
                    'detection': threat_analysis['detection'],
                    'severity': threat_analysis['severity'],
                    'color': threat_analysis['color'],
                })

        if suspicious_events:
            for threat_overview in suspicious_events:

                # NEW: Call Bedrock to analyze the threat
                ai_analysis = analyze_with_bedrock(
                    log_message=threat_overview['message'],
                    threat_type=threat_overview['threat_type'],
                    severity=threat_overview['severity']
                )

                # Build a richer Discord message using AI analysis
                title = f"🚨 {threat_overview['severity']} ALERT: {threat_overview['threat_type'].upper()}"
                description = inspect.cleandoc(f"""
                **Threat Type:** {threat_overview['threat_type']}
                **Detection:** {', '.join(threat_overview['detection'])}

                **__AI Analysis__**
                **Summary:** \n{ai_analysis.get('summary', 'N/A')}\n
                **Attack Type:** \n{ai_analysis.get('likely_attack', 'N/A')}\n
                **Recommended Action:** \n{ai_analysis.get('recommended_action', 'N/A')}\n
                **IP Address:** \n{ai_analysis.get('ip_address') or 'Not found'}
                """)

                webhook_embed(
                    title=title,
                    message_description=description,
                    color=threat_overview['color']
                )

            return {
                'statusCode': 200,
                'body': json.dumps(f'Found and reported {len(suspicious_events)} threats')
            }
        else:
            return {
                'statusCode': 200,
                'body': json.dumps('No threats detected')
            }

    except Exception as e:
        print(f"Error: {e}")
        webhook_embed(
            title="Lambda Error",
            message_description=f"Error analyzing logs: {str(e)}",
            color='ff0000'
        )
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error: {str(e)}')
        }