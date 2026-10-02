# Scam Shield Pakistan – AI Scam Detector

A beginner-friendly web project. The user pastes a suspicious WhatsApp/SMS/email message and gets a risk level, an explanation, warning signs, safety advice and an AI confidence meter. It understands English, Urdu and Roman Urdu.

## Project structure

```
scam-shield-pakistan/
├── index.html        Page structure (all sections)
├── style.css         Dark navy design, responsive
├── script.js         Rule check, API call, results, recent checks
├── api/
│   └── analyze.js    Serverless function: talks to Gemini, holds the secret key
├── package.json      Basic project info (no dependencies)
├── .env.example      Shows which secret is needed (copy to .env.local)
├── .gitignore        Keeps secrets out of GitHub
└── README.md
```

## How it works (good for your presentation)

1. User pastes a message and clicks **Analyze Message**.
2. **Rule-based check** (browser): looks for scam words (English/Urdu/Roman Urdu) and risky links, and gives a score.
3. **AI check**: the browser sends the text to `/api/analyze`. That server function adds the secret API key and asks **Google Gemini** for a structured JSON answer.
4. **Combine**: the rules can raise the AI risk level by one step, never lower it.
5. The result card shows risk level, confidence meter, explanation, highlighted message, warning signs and advice. The check is saved in `localStorage` (on the user's device only).

**Why a serverless function?** Anything in `script.js` is visible to every visitor. If the key were there, anyone could steal it. In `api/analyze.js` the key is read from an environment variable on the server and never sent to the browser.

If the AI is down or you open the page without the backend, the site still works using the rule check only.

## Step 1: Get a Gemini API key

1. Go to https://aistudio.google.com/apikey and sign in with a Google account.
2. Click **Create API key** and copy it.
3. Keep it secret. Do not paste it in any file that goes to GitHub or in chat.

The free tier has usage limits that Google may change, so check the current limits on the Gemini API pricing page. The default model is `gemini-2.5-flash`. If Google retires it, set a newer model name in the `GEMINI_MODEL` variable (see the model list at https://ai.google.dev/gemini-api/docs/models).

## Step 2: Run locally

You need Node.js 18 or newer (https://nodejs.org).

```bash
# 1. Install the Vercel command line tool (once)
npm install -g vercel

# 2. Open the project folder
cd scam-shield-pakistan

# 3. Create your private env file
cp .env.example .env.local        # on Windows: copy .env.example .env.local
# open .env.local and paste your key after GEMINI_API_KEY=

# 4. Start the local server (first time it asks you to log in / link a project: accept the defaults)
vercel dev
```

Open the address it prints (usually http://localhost:3000).

Note: opening `index.html` by double-clicking will show the page, but `/api/analyze` will not exist, so you will only get the rule-based check. Use `vercel dev` for the full project.

## Step 3: Test it

1. Click an example such as **Fake bank** and press **Analyze Message**. Expect **Likely Scam**, a confidence meter, highlighted words and warning signs.
2. Click **Normal bank alert**. Expect **Likely Safe** or at most **Suspicious**.
3. Try the Urdu and Roman Urdu examples.
4. Paste your own message, press **Clear**, and check that the form resets.
5. Reload the page: **Recent checks** should still be listed. Click **Clear history** to remove them.
6. Test the safety setup: open the browser's DevTools, go to Sources/Network and search for your key. It must not appear anywhere.
7. Remove the key from `.env.local`, restart, and confirm you see the "AI check unavailable" notice with rule-only results.

## Step 4: Upload to GitHub

1. Create an account at https://github.com and click **New repository**. Name it `scam-shield-pakistan`. Do not add a README (you already have one).
2. In the project folder run:

```bash
git init
git add .
git commit -m "Scam Shield Pakistan first version"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/scam-shield-pakistan.git
git push -u origin main
```

3. Check on GitHub that `.env.local` is **not** there. The `.gitignore` file blocks it. If you ever uploaded a key by mistake, delete that key in Google AI Studio and make a new one.

## Step 5: Deploy on Vercel (free Hobby plan)

1. Sign up at https://vercel.com using your GitHub account.
2. Click **Add New → Project** and import your `scam-shield-pakistan` repository.
3. Leave **Framework Preset** as **Other**. No build command or output directory is needed.
4. Open **Environment Variables** and add:
   - `GEMINI_API_KEY` = your key
   - (optional) `GEMINI_MODEL` = a model name
5. Click **Deploy**. After about a minute you get a link like `https://scam-shield-pakistan.vercel.app`.
6. Every time you `git push`, Vercel redeploys automatically.

If you add or change an environment variable later, go to **Deployments** and redeploy so the change takes effect.

## Troubleshooting

| Problem | Fix |
|---|---|
| "Server is missing GEMINI_API_KEY" | Add the variable in `.env.local` (local) or Vercel settings, then restart or redeploy |
| "AI service is busy or unavailable" | Free-tier limit reached or wrong model name. Wait a minute or check `GEMINI_MODEL` |
| `/api/analyze` returns 404 | You opened the file directly. Run `vercel dev` |
| Page works but only rule result shows | The AI call failed. Read the yellow notice and the terminal logs |

## Customize

- Add scam words or new rules in the `RULES` list at the top of `script.js`.
- Change colors in the `:root` block of `style.css`.
- Edit the AI instructions in `SYSTEM_PROMPT` inside `api/analyze.js`.

## Limitations (mention these in your report)

- AI can be wrong, and scammers change their wording. The tool is a helper, not proof.
- Keyword rules can give false alarms, so they can only raise the level by one step.
- Anyone can call your public `/api/analyze` link, which may use up your free quota. For a real product, add rate limiting. Messages are limited to 2000 characters.
- Messages are sent to Google's Gemini API for analysis. Tell users not to paste real OTPs, PINs, passwords or CNIC numbers.
- Reporting numbers and websites can change. Confirm them on the official sites (NCCIA, PTA).

## Ideas to extend it for your course

Add a test set of 50 labelled messages and measure accuracy, compare Gemini with the rules alone, add a rate limiter, or add screenshot (image) checking.
