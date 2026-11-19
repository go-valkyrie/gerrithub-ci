# gerrithub-ci

A Cloudflare Worker that runs GitHub Actions for changes under review on [GerritHub](https://review.gerrithub.io), and votes `Verified` on them. GitHub holds no GerritHub credentials.

```text
GerritHub ── webhook ──▶ Worker ── repository_dispatch + ticket ──▶ GitHub Actions
    ▲                     ▲  │                                        │
    │                     │  └─ verifies the OIDC token and ticket ◀──┤ vote job: result + ticket,
    └──── Verified ±1 ────┘     (Worker's own Gerrit account)          │ signed in with GitHub OIDC
```

- **`POST /gerrit/<WEBHOOK_SECRET>`:** GerritHub's `webhooks` plugin posts its events here. The Worker decides which events should run CI. It sends `repository_dispatch` to the GitHub repository GerritHub mirrors, with a **ticket**: an HMAC-signed record of the project, change, patch set, revision and repository.
- **`POST /vote`:** the workflow's `vote` job posts its result and the ticket here, with a GitHub Actions OIDC token as its bearer token. The Worker votes only if three things check out:
  - The token is signed by GitHub and meant for this Worker: its issuer, audience and expiry are checked.
  - The token comes from the expected workflow file, on the expected branch, in the repository the ticket names, from a `repository_dispatch` run.
  - The ticket is one the Worker signed, less than 12 hours ago.

  It then votes with its own Gerrit account. A valid token can't vote on a change the Worker didn't send to CI. Only the trusted workflow on the default branch can vote at all.

## What runs

- **A new patch set** runs when its uploader is in `TRUSTED`.
- **Anyone else's patch set** runs when a trusted reviewer comments `recheck` on it. Untrusted code never reaches CI unless a maintainer asks for it.
- **Other events, and projects missing from `PROJECTS`,** are acknowledged and ignored with a 200, so Gerrit doesn't retry them.
- **Events it will act on** are answered 202 at once; confirming and dispatching happen afterwards, in the background. The webhooks plugin retries any delivery slower than its socket timeout, and every retry would dispatch another run, so the Worker never makes it wait.
- **If Gerrit or GitHub fails,** the Worker retries twice itself, after 1 and 4 seconds, then gives up. A GitHub client error other than 429 isn't retried. The outcome of each event is in the Worker's logs (`npx wrangler tail`, or the dashboard under Workers → gerrithub-ci → Logs), and a maintainer can comment `recheck` to try again.

**Events are confirmed with Gerrit.** The webhooks plugin can't sign its requests, so an event is only a hint. Before dispatching, the Worker fetches the change from Gerrit's REST API as the bot account, and checks the event against it:
- **The patch set:** the revision, patch set number, ref and project must all match the event.
- **For a new patch set:** Gerrit's record of the uploader must be trusted.
- **For a recheck:** Gerrit must show a trusted reviewer's `recheck` on that patch set.

Someone who learned the webhook URL could only make the Worker re-check real events; they couldn't get CI to run untrusted code, or the bot to vote on it. Events Gerrit doesn't confirm are dropped, and the Worker logs why.

In the workflow, the job that runs the change's code gets no secrets and can't request an OIDC token. Only the `vote` job has `id-token: write`.

## Set up

1. **Create a GitHub App** to send the dispatches, under Settings → Developer settings → GitHub Apps.
   - **Permissions:** Repository → Contents: **Read and write**, which `repository_dispatch` needs. Metadata: read is added automatically. Nothing else.
   - **Webhook:** turn it off.
   - **Installation:** only on the mirror repository.
   - **Settings to copy:** note the App ID for `GITHUB_APP_ID`, and generate a private key. GitHub's `.pem` (PKCS#1) works as-is.

   For each dispatch, the Worker signs an app JWT and exchanges it for an installation token limited to that one repository and Contents: write. It caches the token until shortly before it expires. No personal token is involved.

2. **Deploy the Worker.** Every setting is a Worker secret, so this repository holds nothing about your deployment and anyone can deploy it as it is. `wrangler.toml` lists them all, with the optional ones and their defaults.

   ```sh
   mise install          # Node, from mise.toml
   npm ci
   npx wrangler deploy   # the first deploy creates the Worker; it ignores every event until configured
   npx wrangler secret put GITHUB_APP_ID         # the App ID from step 1
   npx wrangler secret put GITHUB_APP_PRIVATE_KEY < app.pem   # the key from step 1
   npx wrangler secret put PROJECTS              # e.g. {"go-valkyrie/vali-scheme": "go-valkyrie/vali-scheme"}
   npx wrangler secret put TRUSTED               # e.g. ["your-gerrit-username"]; prefer usernames, as Gerrit may hide emails
   npx wrangler secret put WEBHOOK_SECRET        # a long random string
   npx wrangler secret put TICKET_SECRET         # another long random string
   npx wrangler secret put GERRIT_USER           # the GerritHub bot account
   npx wrangler secret put GERRIT_HTTP_PASSWORD  # its HTTP password
   ```

   Secrets take effect without redeploying, and later deploys keep them.

3. **Point GerritHub at it.** As project owner, add `webhooks.config` to the project's `refs/meta/config`:

   ```ini
   [remote "gerrithub-ci"]
     url = https://gerrithub-ci.<account>.workers.dev/gerrit/<WEBHOOK_SECRET>
     event = patchset-created
     event = comment-added
     sslVerify = true
   ```

   ```sh
   git fetch origin refs/meta/config:meta-config && git checkout meta-config
   # add webhooks.config, commit
   git push origin HEAD:refs/meta/config
   ```

   The plugin can't send an auth header, so the secret is part of the URL.
   - **Keep it private:** by default only project owners and Gerrit administrators can read `refs/meta/config`. Check that the project's Access page grants no **Read** on `refs/meta/config` to Registered or Anonymous Users.
   - **`sslVerify = true` matters:** GerritHub's default is false, so without it the URL could be sent to an impostor.
   - **If it leaks:** change `WEBHOOK_SECRET` and the `url` together. Since events are confirmed with Gerrit, a leaked URL can't run untrusted code in the meantime.

4. **Add a `Verified` label** to the project's `project.config` on `refs/meta/config`, if it doesn't have one. Grant the bot account permission to vote it.

5. **Add the workflow.** Copy `templates/gerrit-verify.yml` to `.github/workflows/` on the mirror's default branch, and replace its `Check` step with the repository's checks. Set the repository variable `GERRITHUB_CI_URL` to the Worker's URL. It's a variable, not a secret.

   The Worker accepts votes only from that workflow file on that branch. To change either, set the `WORKFLOW` or `BRANCH` secret.

## Develop

```sh
mise run check   # type-check and test
mise run dev     # wrangler dev; put secrets in .dev.vars
```

## Licence

MIT
