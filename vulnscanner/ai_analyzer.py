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
            Analyze this security vulnerability in detail. Include HTTP request and response data:

            Vulnerability Type: {vulnerability_data.get('type')}
            Severity: {vulnerability_data.get('severity')}

            Request Details:
            {json.dumps(request_data, indent=2)}

            Response Details:
            {json.dumps(response_data, indent=2)}

            Please provide a detailed analysis in JSON format with:
            1. Risk assessment - Detailed explanation of the security implications
            2. Potential impact - Comprehensive analysis of possible consequences
            3. Attack vectors - Ways this vulnerability could be exploited
            4. Recommended fixes - Specific code or configuration changes
            5. Best practices - Security guidelines to prevent similar issues
            6. CVSS score - If applicable
            7. Related vulnerabilities - Common attack chains
            8. Technical details - Implementation-specific information
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

    def analyze_request_response(self, request_data, response_data):
        """Analyze HTTP request/response patterns for security implications"""
        try:
            analysis_prompt = f"""
            Analyze these HTTP request and response patterns for security implications:

            Request:
            {json.dumps(request_data, indent=2)}

            Response:
            {json.dumps(response_data, indent=2)}

            Provide analysis in JSON format with:
            1. Security headers assessment
            2. Content security policy evaluation
            3. Authentication mechanism review
            4. Data exposure risks
            5. Input validation concerns
            6. Response pattern anomalies
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
                "status": "HTTP analysis failed"
            }

    def generate_summary(self, vulnerabilities):
        try:
            summary_prompt = f"""
            Analyze these security vulnerabilities and provide a comprehensive summary:

            Vulnerabilities:
            {json.dumps(vulnerabilities, indent=2)}

            Provide a detailed summary in JSON format with:
            1. Overall security posture
            2. Critical findings prioritized by risk
            3. Attack surface analysis
            4. Remediation priorities
            5. Security recommendations
            6. Risk metrics
            7. Compliance implications
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