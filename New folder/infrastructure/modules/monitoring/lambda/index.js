exports.handler = async (event) => {
    console.log('Event:', JSON.stringify(event, null, 2));
    
    // Parse SNS message
    const message = event.Records[0].Sns.Message;
    
    // Get environment variables
    const slackWebhookUrl = process.env.SLACK_WEBHOOK_URL;
    const slackChannel = process.env.SLACK_CHANNEL;
    
    // Create Slack message
    const slackMessage = {
        channel: slackChannel,
        text: `*CloudWatch Alarm*\n${message}`,
        attachments: [
            {
                color: "#FF0000",
                fields: [
                    {
                        title: "Alarm Details",
                        value: message,
                        short: false
                    }
                ]
            }
        ]
    };
    
    // In a real implementation, you would send the message to Slack here
    console.log('Slack message:', JSON.stringify(slackMessage, null, 2));
    
    return {
        statusCode: 200,
        body: JSON.stringify('Message sent to Slack'),
    };
};
