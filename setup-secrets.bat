@echo off
setlocal

:: ============================================================
:: HOW TO GET THESE VALUES:
::
:: 1. APPLE_CERTIFICATE (base64 P12)
::    - Keychain Access > My Certificates > "Developer ID Application: ..."
::    - Right-click > Export > save as .p12 with a password
::    - Then: base64 -i cert.p12 | pbcopy   (macOS)
::      or:  certutil -encode cert.p12 tmp.b64 && type tmp.b64 (Windows)
::    - Paste the base64 string below
::
:: 2. APPLE_CERTIFICATE_PASSWORD
::    - The password you set when exporting the .p12 above
::
:: 3. APPLE_ID
::    - Your Apple Developer account email (e.g. you@example.com)
::
:: 4. APPLE_PASSWORD (app-specific password)
::    - Go to: https://appleid.apple.com/account/manage
::    - Sign In & Security > App-Specific Passwords > Generate
::    - Name it e.g. "github-notarize", copy the generated password
::
:: 5. APPLE_TEAM_ID
::    - Go to: https://developer.apple.com/account
::    - Membership Details > Team ID (10-char alphanumeric)
:: ============================================================

set REPO=ssoj13/filesystem-mcp-rs

:: Fill in your values below (same as in playa repo)
set APPLE_CERTIFICATE=PASTE_BASE64_P12_HERE
set APPLE_CERTIFICATE_PASSWORD=PASTE_PASSWORD_HERE
set APPLE_ID=PASTE_APPLE_ID_HERE
set APPLE_PASSWORD=PASTE_APP_SPECIFIC_PASSWORD_HERE
set APPLE_TEAM_ID=PASTE_TEAM_ID_HERE

echo Setting secrets on %REPO%...

echo %APPLE_CERTIFICATE%| gh secret set APPLE_CERTIFICATE --repo %REPO%
echo %APPLE_CERTIFICATE_PASSWORD%| gh secret set APPLE_CERTIFICATE_PASSWORD --repo %REPO%
echo %APPLE_ID%| gh secret set APPLE_ID --repo %REPO%
echo %APPLE_PASSWORD%| gh secret set APPLE_PASSWORD --repo %REPO%
echo %APPLE_TEAM_ID%| gh secret set APPLE_TEAM_ID --repo %REPO%

echo Done! Verifying...
gh secret list --repo %REPO%

endlocal
