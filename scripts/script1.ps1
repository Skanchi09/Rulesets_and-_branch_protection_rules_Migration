# Define the JSON body as a PowerShell literal string
$body = @'
{
  "required_status_checks": {
    "strict": false,
    "contexts": []
  },
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": false,
    "require_code_owner_reviews": true,
    "require_last_push_approval": false,
    "required_approving_review_count": 1
  },
  "required_signatures": false,
  "enforce_admins": true,
  "required_linear_history": false,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "block_creations": false,
  "required_conversation_resolution": false,
  "lock_branch": false,
  "allow_fork_syncing": false,
  "restrictions": null
}
'@

# Set the token and headers
$headers = @{
    "Accept" = "application/vnd.github+json"
    "Authorization" = "token add my token"  
    "Content-Type" = "application/json"
}

# Send the PUT request using Invoke-RestMethod
$response = Invoke-RestMethod -Uri "https://api.github.com/repos/saideep11111/source2/branches/other/protection" `
                              -Method Put `
                              -Headers $headers `
                              -Body $body

# Display the response
$response
