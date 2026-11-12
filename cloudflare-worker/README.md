# CGTEVIL — Secure phone OTP

This Worker verifies phone ownership only. It does not process payments, authorize carrier-balance transfers, initiate USSD actions, or confirm donations.

## Deploy
From the repository root, enter the Worker folder and install Wrangler:
```sh
cd cloudflare-worker
npm install -g wrangler
wrangler login
```

Set the Resala API key as a Worker secret before deploying:
```sh
wrangler secret put RESALA_API_KEY
```
The CLI prompts for the value. Never put the key in HTML, GitHub source, or chat.

Then deploy:
```sh
wrangler deploy
```
Copy the deployed Worker URL shown by Wrangler.

## Resala configuration
- `RESALA_SERVICE_NAME` is the app/service label appended to the OTP message; set it to the desired CGTEVIL label in `wrangler.toml`.
- `RESALA_TEST = "true"` adds Resala's `?test` query flag. Resala's test mode sends no SMS and makes no charge. Set it to `"false"` only when ready for a real SMS test.
- The optional Resala sender ID is separate from `RESALA_SERVICE_NAME` and must be registered/approved by Resala before use.

Resala expects `service_name`, `len`, and `test` as URL query parameters on `POST https://dev.resala.ly/api/v1/pins`, with only the international phone number in the JSON body. The Worker stores a keyed HMAC of the PIN using the server-side Resala secret; it never returns or logs the PIN.

## Connect the website
In `index.html`, replace the placeholder in `OTP_API_BASE` with your deployed Worker URL, then commit the HTML change to the GitHub Pages branch.

## Testing
With `RESALA_TEST = "true"`, you can confirm the API accepts the request without sending or charging, but no SMS arrives, so a full user-entered OTP verification cannot be completed in test mode. For an end-to-end test, set `RESALA_TEST = "false"` and send one test OTP to a phone you control; Resala's published price is 0.10 LYD per SMS. Do not retry automatically after ambiguous network errors.

## Security
- PINs are never returned to the browser or logged.
- PIN HMACs expire after 5 minutes and are consumed after success.
- Each phone number has a 60-second resend cooldown and at most 5 verification attempts.
- CORS is restricted to the configured website origin.
- Phone verification is not payment verification; never show a donation as paid without confirmation from a legitimate payment provider.
