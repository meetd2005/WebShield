import os
from openai import OpenAI
import json

# the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
# do not change this unless explicitly requested by the user
class VulnerabilityAnalyzer:
    def __init__(self):
        self.client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

    def analyze_vulnerability(self, vulnerability_data, request_data, response_data):
        try:
            analysis_prompt = f"""
            Analyze this security vulnerability in detail:
            
            Vulnerability Type: {vulnerability_data.get('type')}
            Severity: {vulnerability_data.get('severity')}
            
            Request Details:
            {json.dumps(request_data, indent=2)}
            
            Response Details:
            {json.dumps(response_data, indent=2)}
            
            Please provide a detailed analysis in JSON format with the following information:
            1. Risk assessment
            2. Potential impact
            3. Recommended fixes
            4. Best practices to prevent this vulnerability
            5. Additional security considerations
            """

            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[{
                    "role": "user",
                    "content": analysis_prompt
                }],
                response_format={"type": "json_object"}
            )
            
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            return {
                "error": str(e),
                "status": "Analysis failed"
            }

    def generate_summary(self, vulnerabilities):
        try:
            summary_prompt = f"""
            Analyze these security vulnerabilities and provide a comprehensive summary:
            
            Vulnerabilities:
            {json.dumps(vulnerabilities, indent=2)}
            
            Please provide a summary in JSON format with:
            1. Overall security posture
            2. Critical findings
            3. Remediation priorities
            4. Security recommendations
            """

            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[{
                    "role": "user",
                    "content": summary_prompt
                }],
                response_format={"type": "json_object"}
            )
            
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            return {
                "error": str(e),
                "status": "Summary generation failed"
            }
