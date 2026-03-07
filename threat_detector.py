import os
import json
import base64
import gzip
from discord_webhook import DiscordWebhook, DiscordEmbed

# Get webhook URL from Lambda environment variables instead of .env file
WEBHOOK_URL = os.environ.get("WEBHOOK_URL")

def webhook_embed(title, message_description, color=None):
    webhook = DiscordWebhook(url=WEBHOOK_URL)
    embed = DiscordEmbed(
        title=title, 
        description=message_description,
        color='03b2f8')
    webhook.add_embed(embed)
    webhook.execute()
    return

def analyze_auth_log(log_message):
    message = log_message.lower()

    # Detect threat patterns
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
    
    # Return dict with is_threat=False instead of just False
    return {'is_threat': False}


"""REQUIRED FUNCTION TO RUN"""
def lambda_handler(event, context):
    try:
        # Decode CloudWatch Logs data
        compressed_data = base64.b64decode(event['awslogs']['data'])
        log_data = json.loads(gzip.decompress(compressed_data))
        
        log_events = log_data['logEvents']
        log_group = log_data['logGroup']

        suspicious_events = []

        # Analyze each log entry
        for log_event in log_events:
            message = log_event['message']
            threat_analysis = analyze_auth_log(message)
            
            if threat_analysis['is_threat']:
                suspicious_events.append({
                    'timestamp': log_event['timestamp'],
                    'message': message,
                    'threat_type': threat_analysis['type'],
                    'severity': threat_analysis['severity'],
                    'color': threat_analysis['color']
                })
        
        # Send alerts for suspicious events
        if suspicious_events:
            for event_data in suspicious_events:
                title = f"{event_data['severity']} ALERT: {event_data['threat_type'].upper()}"
                description = f"```{event_data['message']}```\n\n**Log Group:** {log_group}"
                
                webhook_embed(
                    title=title,
                    message_description=description,
                    color=event_data['color']
                )
            
            return {
                'statusCode': 200,
                'body': json.dumps(f'Found and reported {len(suspicious_events)} threats')
            }
        else:
            # No threats found
            return {
                'statusCode': 200,
                'body': json.dumps('No threats detected')
            }
            
    except Exception as e:
        print(f"Error: {e}")
        webhook_embed(
            title="Lambda Error",
            message_description=f"Error analyzing logs: {str(e)}",
            color='ff0000'  # Red
        )
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error: {str(e)}')
        }