import subprocess

def run_web_scan(target_url):
    try:
        # Run Nikto web scan
        nikto_command = ["nikto", "-h", target_url]
        nikto_result = subprocess.run(nikto_command, capture_output=True, text=True)

        # Run OWASP ZAP scan using zap-cli
        zap_command = ["zap-cli", "quick-scan", target_url]
        zap_result = subprocess.run(zap_command, capture_output=True, text=True)

        # Combine both results
        result = {
            "nikto_result": nikto_result.stdout,
            "zap_result": zap_result.stdout
        }
        return result
    except Exception as e:
        return {"error": str(e)}
