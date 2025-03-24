# Replace this with your actual VirusTotal API Key
$apiKey = 'YOUR_VIRUSTOTAL_API_KEY'

# Function to check if a URL is phishing
function Check-URL-Phishing {
    param (
        [string]$url
    )

    $body = @{
        'url' = $url
        'apikey' = $apiKey
    }

    # API Endpoint for VirusTotal URL Check
    $urlCheckEndpoint = 'https://www.virustotal.com/vtapi/v2/url/scan'

    try {
        # Send request to VirusTotal API to check the URL
        $response = Invoke-RestMethod -Uri $urlCheckEndpoint -Method Post -Body $body

        # Check if the URL is flagged as phishing
        if ($response.response_code -eq 1) {
            Write-Host "$url is safe."
        } else {
            Write-Host "$url is flagged as phishing."
        }
    }
    catch {
        Write-Host "Error querying VirusTotal for ${url}: $_"
    }
}

# Test with a single URL (replace this with the URL you want to check)
$testUrl = 'http://example1.com'  # Example URL to test

# Call the function to check the URL
Check-URL-Phishing -url $testUrl
