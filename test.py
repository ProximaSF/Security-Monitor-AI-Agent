import os
import json
import inspect
import boto3
from discord_webhook import DiscordWebhook, DiscordEmbed
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("AWS_BEARER_TOKEN_BEDROCK")
WEBHOOK_URL = os.getenv("WEBHOOK_URL")
#WEBHOOK_URL = os.environ.get("WEBHOOK_URL")

bedrock = boto3.client("bedrock-runtime", region_name="us-east-1")

def webhook_embed(title, message_description, color=None):
    webhook = DiscordWebhook(url=WEBHOOK_URL)
    embed = DiscordEmbed(
        title=title, 
        description=message_description,
        color='03b2f8')
    webhook.add_embed(embed)
    webhook.execute()
    return

def read_log():
    file_path = "auth.log"
    with open(file_path, "r", encoding='utf-8') as f:
        log_content = f.read()
        return log_content
    
def write_ai_output(ai_result):
    file_path = 'ai_output.txt'
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(ai_result)
        return


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


    write_ai_output(raw_text)


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


def main():
    log_message = read_log()
    threat_overview = analyze_auth_log(log_message)
    print("Running...")
    
    if threat_overview['is_threat']:  # ✅ fixed key name

        # ✅ Now actually calling Bedrock
        ai_analysis = analyze_with_bedrock(
            log_message=log_message,
            threat_type=threat_overview['type'],
            severity=threat_overview['severity']
        )

       

        title = f"🚨 {threat_overview['severity']} ALERT: {threat_overview['type'].upper()}"
        message_description = inspect.cleandoc(f"""
            **Threat Type:** {threat_overview['type']}
            **Detection:** {', '.join(threat_overview['detection'])}

            **__AI Analysis__**
            **Summary:** \n{ai_analysis.get('summary', 'N/A')}\n
            **Attack Type:** \n{ai_analysis.get('likely_attack', 'N/A')}\n
            **Recommended Action:** \n{ai_analysis.get('recommended_action', 'N/A')}\n
            **IP Address:** \n{ai_analysis.get('ip_address') or 'Not found'}
        """)

        webhook_embed(title, message_description, threat_overview['color'])

    else:
        webhook_embed("✅ Threat Overview", "No threat found")


main()