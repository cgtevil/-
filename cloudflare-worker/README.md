# CGTEVIL — Secure phone OTP

This Worker verifies phone ownership only. It does not process payments, authorize carrier-balance transfers, initiate USSD actions, or confirm donations.

## Deploy
Install Wrangler, sign in, and deploy from this folder:
```sh
npm install -g wrangler
wrangler login
wrangler deploy
```
Copy the deployed Worker URL.

## Resala secret
Set the API key securely (the CLI prompts for its value):
```sh
wrangler secret put RESALA_API_KEY
```
Never put the key in HTML, GitHub source, or chat. Set `RESALA_SERVICE_NAME` to the service name configured in your Resala account. Keep `RESALA_TEST = "true"` while testing; set it to `false` only after confirming the account configuration and test behavior.

## Connect the website
In `index.html`, replace the placeholder in `OTP_API_BASE` with your deployed Worker URL, then commit the HTML to the GitHub Pages branch.

## Resala response
The Worker calls `POST https://dev.resala.ly/api/v1/pins` and expects a PIN in `pin` or `data.pin`. Confirm the exact response and service-name requirements against your Resala account documentation before live use.

## Security
- PINs are never returned to the browser or logged.
- PIN hashes expire after 5 minutes and are consumed after success.
- Each phone number has a 60-second resend cooldown and at most 5 verification attempts.
- CORS is restricted to the configured website origin.
- Phone verification is not payment verification; never show a donation as paid without confirmation from a legitimate payment provider.
