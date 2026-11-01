# Kept Vault

Your private vault for the **Kept** trading journal. It runs in **your own Cloudflare account** and holds:

- your journal (trades, notes, reviews, shared days)
- your Databento key (for trade replay) and Anthropic key (for AI review)
- your saved replay data

The Kept app talks to this vault straight from your browser. Kept's servers never see your journal, your password or your keys.

## Set it up

Follow the step-by-step guide: **https://app.getkeptjournal.com/setup**

The guide's **Deploy to Cloudflare** button copies this vault into your own Cloudflare and GitHub, creates your private database, and asks for:

| Secret | What it is |
| --- | --- |
| `VAULT_PASSWORD` | A password you make up (8+ characters). You type it into Kept to open your journal. |
| `DATABENTO_KEY` | Optional. Your Databento API key, for trade replay. Type `none` to skip. |
| `ANTHROPIC_KEY` | Optional. Your Anthropic API key, for AI review. Type `none` to skip. |

You can add or change these later in Cloudflare: **Workers & Pages → kept-vault → Settings → Variables and Secrets**.

## What's in here

- `src/index.js`: the whole vault. It's small on purpose, so anyone can read it and see it doesn't send your data anywhere.
- `wrangler.json`: tells Cloudflare to create the `kept-vault` database. `APP_ORIGINS` is the Kept website allowed to open your vault.

## Delete it

Delete the `kept-vault` Worker in Cloudflare, then delete the `kept-vault` database under **Storage & Databases → D1**. Nothing is stored anywhere else.

Kept is a journal, not financial advice.
