CAMPUSGUARD AI: HOW THE SYSTEM WORKS
For the team, in plain English. English copy of "Penjelasan Sistem.md". Updated 13 November 2026.
============================================================================================

Contents:
   1. What CampusGuard AI is
   2. The pipeline, from input to result
   3. The foundation: the rule engine
   4. The Scan tab
   5. The Analyst tab
   6. The Evaluation tab and the current numbers
   7. The AI layer (Gemini): what changes when it is on
   8. Campaign memory and privacy
   9. Limits we must admit
  10. Questions judges might ask

Every accuracy number comes from synthetic data we made ourselves, not from real phishing.


1. WHAT CAMPUSGUARD AI IS
--------------------------------------------------------------------------------------------

Name      CampusGuard AI
Tagline   AI-Powered Email Security for Students
Problem   Students receive fake emails that pretend to come from their university: password
          resets, scholarships, fees, mailbox quotas. One click on a fake link can hand over
          a university account.

A student pastes a link, uploads an email saved as PDF, or uploads an .eml file. The app
answers three things: how dangerous it is, why (with quotes from the email), and what to do now.

One sentence for the judges:
  "CampusGuard AI is an agentic system. A rule engine checks the technical facts (who sent
  it, where the links go, which scam script it follows), then the Gemini AI model reads the
  message and explains its reasoning. Without the AI, the system keeps working on rules and
  tells the user."

Three tabs:
  Scan        for students, results in plain language
  Analyst     for technical people, every agent step shown live
  Evaluation  measures how often the app is right on a labelled dataset


2. THE PIPELINE, FROM INPUT TO RESULT
--------------------------------------------------------------------------------------------

This is what "agentic" means here: an orchestrator runs several tools in order and combines
their results into one decision. For emails and PDFs:

  1. Input cleaning (sanitizer)
     HTML stripped, links and attachments collected, text hidden with CSS noted, sender and
     recipient addresses read.

  2. Loading the agent's playbooks
     A base prompt and two playbooks written as .md files (content-analysis.md and
     scam-scoring.md). The rule engine in the code follows the same playbooks, so Gemini and
     the rules use an identical rubric.

  3. Sender check (tool 1)
     Who sent this, and can it be proven? See section 3B.

  4. Link and attachment scan (tool 2)
     Where do the links go, and is the domain a lookalike? See section 3C.

  5. Campaign memory (tool 3)
     Has this attack pattern been seen before? See section 8.

  6. Scam scripts (tool 4)
     Does the wording follow a known scam script? See section 3D.

  7. Message reader
     Gemini (with an API key) or keyword rules (without one) scores the wording part. See
     sections 3E and 7.

  8. Final score, level, result card
     The four components are added, minimum scores applied, the level set and the result
     card built. HIGH or CRITICAL results are saved to campaign memory.

A pasted link takes the short path: the link scanner, then the result card.


3. THE FOUNDATION: THE RULE ENGINE
--------------------------------------------------------------------------------------------

The rule engine is the foundation. It always runs, with or without the AI, and every number
is open. Without an API key, this is the whole system.

3A. THE SCORE FORMULA

  Final score 0 to 100 = the sum of four components, then minimum scores (floors), then cut
  at 100.

    Component           Maximum    Question it answers
    ------------------  ---------  ---------------------------------------------
    Sender                    35   Who sent this, and can it be proven?
    Links and files           30   Where do the links go?
    Wording                   35   What does the email ask for, and how?
    Campaign memory           15   Has this pattern been seen before?

  Minimum scores (applied after the sum):
    Known scam script and the sender or link can't be verified       at least 60
    Executable attachment (.exe, .scr, .js and the like)              at least 85
    Prompt-injection attempt                                          at least 88

  Levels and the labels students see:
    85 - 100    CRITICAL   Likely scam
    60 - 84     HIGH       Suspicious email
    30 - 59     MEDIUM     Unverified sender
    0 - 29      LOW        No red flags found, or "Low risk" when small signs were found

  A score of 60 or more counts as phishing on the Evaluation tab. That line can be changed
  with PHISHING_THRESHOLD in .env.

3B. SENDER COMPONENT (MAX 35)

  Three questions, kept separate:

  Authenticated?    DMARC pass, or SPF and DKIM both pass. The domain really sent it. Only
                    .eml files carry these headers. PDFs and pasted text don't; their status
                    is "unavailable" and is not penalised.

  Who is the domain? The trusted list (155 domains: 151 real universities including
                    ntpu.edu.tw, plus Microsoft 365 sign-in, microsoft.com,
                    accounts.google.com, github.com). Or a real university domain (.edu,
                    .ac.id, .edu.tw and so on; these endings can't be registered by just
                    anyone). Or free webmail (gmail, yahoo, outlook): anyone can open one, so
                    a DMARC pass only proves "sent through Gmail", not who wrote it. Or an
                    unknown domain.

                    The trusted list can be edited with the "Trusted domains" button on the
                    Analyst tab. PayPal, Stripe and google.com are deliberately not on it
                    (docs.google.com is often used for phishing forms), so a real PayPal link
                    shows Unverified: safe, just not verified. The list is kept in memory; if
                    REDIS_URL is set and that Redis already holds an older list, the older list
                    is used.

  Verified?         Authenticated AND (on the trusted list OR a real university domain that
                    isn't a lookalike). Only a verified sender escapes the scam-script minimum
                    score.

  Points:
    Lookalike domain                                                   +20
      Five kinds: brand lookalike (paypa1-support.com), dressed up as a university address
      (westbrook-edu.com, ntpu.edu.tw-login.com), a digit swapped into a university name
      (westbr0ok.edu, harr0wgate.ac.uk), a lookalike of a trusted-list domain (ntpu-login.com,
      ntpu.edu.tvv, harvrad.edu, ntpuedu.tw), and a domain carrying the recipient's own university name
      off its real domain (harrowgate-it.help sent to @harrowgate.ac.uk). The last one uses
      the recipient's address, so it needs no campus configuration.
    DMARC fail, or "none" on a lookalike/trusted domain                +15
      (+8 when it is merely "none" on an unknown domain)
    Trusted domain but authentication failed (spoofed header)          +15
    SPF fail                                                           +8
    DKIM fail                                                          +7
    Sender domain built from security words                            +10 (+5 for one word)
      Examples: webmail-upgrade-center.com, exec-mailbox.org, fastmail-secure.net.
    Display name claims a title or a brand                             +12 (+8 in a PDF)
      "Prof.", "Dr.", "Dean", "CFO", "IT Support", "Accounts", "Team", "Office" from a free
      webmail address, or from an unknown domain that isn't authenticated. Never for trusted
      or real-university senders: "Dr. Sutanto" from westbrook.edu is just a professor.
    Reply-To on a different domain from the sender                     +12
    Return-Path on a different domain from the sender                  +5

  A verified sender with no odd Reply-To: this component is 0.

3C. LINKS AND FILES COMPONENT (MAX 30)

  The HIGHEST value among all links is used, then the two extras below are added.

    Lookalike domain (the same five kinds as 3B)                       30
    Listed by Google Safe Browsing (needs a separate key)              30
    Login path on a risky TLD                                          30
    Raw IP address (http://45.83.164.69/login)                         28
    Shortened link (bit.ly, tinyurl, t.co and others)                  22
      Hides the real destination. The app does not follow redirects.
    Domain built from security words                                   22 (12 for one word)
      drive-docs-shared.com, wallet-verify-center.com, secure-docs-share.net.
    A listed university's name on another ending, plus a sign-in hint 30
      ntpu.com/login, sso.ntpu.com, sso.ntpu.tw. Anyone can buy these addresses.
      Without a sign-in hint (ntpu.net, columbia.com) it is only 12 and stays Unverified,
      because the same name can belong to a real company (columbia.com is a clothing
      brand). Names of 4 or more letters only (ui.com is the company Ubiquiti).
    Punycode (look-alike letters from other alphabets)                 20
    Often-abused TLD (.xyz, .top, .click, ...)                         18
    Login path on an unknown domain                                    18
    Unencrypted HTTP                                                   10

  Extras:
    Link text doesn't match where the link goes                        +15
    Executable attachment                                              +25

  First-party links:
    A link on the sender's own domain, when the sender is authenticated (or the headers are
    simply absent, as in a PDF) and is not a lookalike or a security-word domain. For such
    links the two weak signals (login path, http) are waived. Example:
    portal.westbrook.edu/password/reset from no-reply@westbrook.edu is not a lure. The
    reasoning: forging the From line only helps an attacker if the link goes somewhere else.

  Links to trusted domains add nothing.

  A link pasted on its own (no email) is scored differently: the highest points in the list
  above, times 3, capped at 100. So a lookalike domain (30) shows 90, a security-word domain
  (22) shows 66, one security word (12) shows 36, and a login path on an unknown domain (18)
  shows 54. The "@" trick is at least 75, a misspelled sign-in page on a real domain stays at
  40, and a trusted domain is 0. A "Suspicious link" label is never below 60.

3D. KNOWN SCAM SCRIPTS (MINIMUM SCORE 60)

  The components above are additive, so a scam that relies on wording alone could never
  reach 60. These eight scripts are what security teams treat as scams on sight. When one
  matches AND the context can't vouch for the email, the final score is at least 60.

    Script                       What matches                          Minimum applies when
    ---------------------------  ------------------------------------  --------------------------
    Gift-card request            buy gift cards, send codes/photos     sender not verified
    Fee to release money         "processing fee", "fee to release",   sender not verified
                                 with a prize/grant/refund context
    Change of bank details       "we changed our bank/ACH details",    sender not verified, or
                                 "new routing number"                  Reply-To elsewhere
    Urgent or secret money       wire/transfer/send money + urgency    sender not verified,
    transfer                     or secrecy ("keep this between us",   display-name spoof, or
                                 "do not call")                        Reply-To elsewhere
    Asks for ID or banking       fill a form with student ID, direct   sender not verified and
    details                      deposit, card, passport               banking details asked
    "Are you available?"         two or more of: availability check,   no links, sender not
    opener                       vague favour, demand for a fast reply verified
                                 or a move to WhatsApp/LINE, "in
                                 meetings, don't call"
    Credential lure              asks to sign in/verify/reset/unlock,  a link that is not trusted,
                                 threatens suspension, or says the     not first-party and not a
                                 mailbox is full                       university domain; or a
                                                                       lookalike sender; or the
                                                                       link couldn't be read (PDF)
                                                                       and the sender is neither a
                                                                       university nor trusted
    Missed-delivery notice       "could not be delivered",             a shortened or suspicious
                                 "reschedule delivery"                 link, sender not verified

  Each script also adds points to the wording component (3E) and quotes the matching
  sentence as evidence. The minimum shows in the result as "Known scam script".

  Why this is safe from false alarms: a verified sender (real university or trusted list,
  authenticated) whose links go only to its own domain or trusted domains never gets a
  minimum score. A real password reset from no-reply@westbrook.edu stays LOW. A trusted
  domain that fails authentication (spoofed header) is NOT verified, so it still gets one.

3E. WORDING COMPONENT, RULE MODE (MAX 35)

    Urgency (time pressure)                       7, or 11 with two or more keywords
    Threats and bad consequences                  6, or 9 with two or more keywords
    Pretending to be a brand or authority         8
    BEC pattern (CEO, gift card, payroll)         6 (if not already impersonating a brand)
    Generic greeting or deceptive link text       4
    Prompt-injection attempt                      5
    Asking for money                              8
    Asking to sign in or verify an account        4 (if not asking for money)
    Scam scripts (3D): gift card 12, fee 12, bank change 10, transfer 12, ID/banking details
    10 (6 without banking), opener 10 (4 for one marker), credential lure 10 + 8 threat + 8
    mailbox full, missed delivery 8

  The total is cut at 35.

  Benign cap: a verified sender, no odd Reply-To, all links trusted or first-party, no
  suspicious link and no risky attachment: the wording component is capped at 4 and no
  minimum score applies. A professor's reminder saying "submit immediately" stays LOW.

  The rule keywords are English only. An email in Chinese or Indonesian is judged by its
  sender and links alone (neither depends on language), unless Gemini is on.

3F. CAMPAIGN MEMORY (MAX 15)

  +15 if the same attack pattern was judged HIGH or CRITICAL before. See section 8.

3G. WORKED EXAMPLES

  Gift card from "Prof. Omar Sutanto" <prof.sutanto5@gmail.com>, DMARC pass:
    Sender: "Prof." display name on free webmail                        12
    Links: none                                                          0
    Wording: gift card 12 + opener 10 + urgency 7 + BEC 6 ...           cut at 35
    Sum 47. Gift-card script, sender not verified: at least 60. Final 60, Suspicious email.
    (With one more sign, say a Reply-To elsewhere, it lands in the 70s.)

  Real password reset from no-reply@westbrook.edu, DMARC pass, link portal.westbrook.edu:
    Sender verified (real university, authenticated)                     0
    Link first-party, weak signals waived                                0
    Wording: "reset your password" 10, "within 24 hours" 7, capped at 4 (benign cap)
    Credential-lure script matches, but the link is safe: no minimum. Final 4, LOW.

  Mailbox full from admin@webmail-upgrade-center.com, link http://45.83.164.69/webmail/login:
    Sender: DMARC none 8 + DKIM none 7 + security-word domain 10 + "Team" 12    35
    Links: raw IP 28, login path on a malicious domain                           30
    Wording: mailbox full 8 + threat 8 + sign in 10 + generic greeting 4 ...     cut at 35
    Final 100, Likely scam.


4. THE SCAN TAB
--------------------------------------------------------------------------------------------

Three ways in:

  Link         Paste a URL. The result is one of three labels:
                 Official domain match   on the trusted list, score 0. For a subdomain
                                         (lms.ntpu.edu.tw) it says "belongs to ntpu.edu.tw.
                                         We checked the address, not whether this page
                                         exists."
                 Suspicious link         a strong sign (lookalike, shortened link, security-
                                         word domain, raw IP, punycode, risky TLD, an "@"
                                         trick, a university's name on another ending with a
                                         sign-in hint), score always at least 60
                 Unverified domain       unknown, not necessarily bad
               A link is never "Likely scam"; the strongest link label is "Suspicious link".
               A login page on an unknown domain is deliberately "Unverified", because real
               services such as canvas.instructure.com/login look exactly like that.

               A misspelled sign-in page on the real domain (ssa.ntpu.edu.tw instead of sso):
               Unverified, score 40, with "looks like a misspelling of sso.ntpu.edu.tw. Check
               the spelling." It is not called Suspicious, because only NTPU can create
               addresses ending in .ntpu.edu.tw; an attacker can't put a page there. The risk
               is not fraud but that the student doesn't reach the sign-in page they meant.
               Compared against: sso, login, signin, portal, webmail, auth, plus the subdomain
               of CAMPUS_PORTAL_URL in .env when it is set. Real NTPU subdomains (www, my, lms,
               cof, sea.cc) stay Official.

  Email PDF    Open the email, Print, Save as PDF, upload (up to 5 MB). A "Microsoft Print to
               PDF" file is a picture and is rejected with an explanation. A PDF carries no
               authentication headers and sometimes keeps only the printed link text, not the
               target. Both are listed under "What we couldn't check".

  Email file   Drop an .eml on the text box, pick one with "browse your computer", or paste
               the email. Pasted text without headers means the sender can't be checked, and
               a link hidden behind "click here" is lost.
               Word files (.docx) are not accepted: save the email as a PDF or .eml.

"Try an example" in each mode:
  Link         Fake university login (Suspicious link), Fake PayPal (Suspicious link), Real
               university website www.ntpu.edu.tw (Official domain match), Misspelled
               sign-in page ssa.ntpu.edu.tw (Unverified, 40), Same name, wrong ending
               ntpu.com/login (Suspicious link), Unknown site (Unverified domain)
  Email PDF    Scam that hides instructions for scanners (Likely scam, 88), Scholarship that
               needs a fee first (Suspicious email, 75), Ordinary email (No red flags found)
  Email file   Eight samples: 1, 2, 3, 5, 6 are phishing (88 to 100, Likely scam), 4 is a
               real GitHub notice (0), 7 and 8 are unverified senders (58 and 56, Unverified
               sender)

Every result contains:
  Summary card          label, main finding (what the email asks for), why it matters, next
                        steps
  How we decided        the four-component score, a "Known scam script" line when one
                        applies, sentences highlighted from the email, tool evidence,
                        confidence
  What we couldn't      what could not be checked. The more there is, the lower the
  check                 confidence.

A green "Checked with AI reasoning" note or an amber note explaining why the AI wasn't used
is always shown, so the user knows which mode did the work.

Scanning the same email or PDF twice raises the score by 15 (campaign memory, section 8).

One-university mode (optional, three lines in .env, example in .env.example):
  CAMPUS_NAME, CAMPUS_DOMAINS, CAMPUS_PORTAL_URL. Without them the app runs generically for any
  university, which is enough for a demo. When set (for example for NTPU):
    - A domain one or two letters away from the campus domain (ntpuu.edu.tw, ntpu.org) is
      called Suspicious.
    - The header becomes "...for National Taipei University Students".
    - An "Open official campus portal" button appears on suspicious or login-page results.
    - A misspelled login subdomain is also compared with the subdomain of CAMPUS_PORTAL_URL.


5. THE ANALYST TAB
--------------------------------------------------------------------------------------------

For technical judges. Pick a sample or paste an email, then "Analyze (live stream)". Each agent
step appears live:

  INPUT_SANITIZATION    email cleaned, links and attachments counted
  AGENT_FRAMEWORK       base prompt and the two playbooks loaded
  TOOLS_EXECUTION       sender check, then link scan, with each component's score
  MEMORY_LOOKUP         campaign fingerprint lookup
  PATTERNS_MATCHED      scam scripts matched and their minimum score (if any)
  LLM_REASONING         prompt assembled and Gemini called
  LLM_FALLBACK          only when Gemini was not used, with the reason
  COMPLETED             verdict, score, time

Below: four score tiles plus the scam-script line, the sender check with SPF/DKIM/DMARC
badges, each link's verdict, evidence marked "found in the email", sanitizer notes, and
campaign memory. "Skill playbooks (.md)" shows the playbooks in use; "Trusted domains" shows and
edits the trusted list.

The "Use Gemini reasoning" box decides whether a Gemini call is attempted.


6. THE EVALUATION TAB AND THE CURRENT NUMBERS
--------------------------------------------------------------------------------------------

6A. DATASET

  260 synthetic items: 130 phishing and 130 safe, from 5 fictional universities that are
  deliberately NOT on the trusted list. Input kinds: 150 .eml files, 30 PDFs, 20 pasted
  texts, 60 links. Three difficulty levels. Split in two: dev, 128 items (for tuning) and
  test, 132 items (final numbers). Regenerates identically with seed 42. The safe items are
  built to look like phishing: real password resets, bank alerts saying "unusual activity,
  sign in to review", course reminders saying "submit immediately", overdue Stripe invoices.

6B. HOW TO USE THE TAB

  Run the app on the dataset
    Choose 10, 50, 100, 200 random or All items and press Run. The running app judges each
    item; every number below comes from that run only. Random picks are half phishing, half
    safe, and don't repeat while the browser tab is open. Without Gemini, 260 items finish in
    a few seconds. "Use Gemini if available" is off by default because each item is one call.

  Right and wrong         caught, missed, false alarm, correctly allowed
  What the numbers mean   accuracy, precision, recall, F1, each with a plain sentence
  By input type and       the same results by input kind and difficulty
  difficulty
  Every item in this run  every item and the app's answer; tick "Only wrong answers"; click
                          a row for the reasoning
  Add items to the        add .eml, .pdf, .txt (up to 5 MB) or links labelled Phishing or
  dataset                 Legit. Stored in eval/added/, never pushed to GitHub.

6C. CURRENT NUMBERS, RULE MODE, THRESHOLD 60

  All 260 items (All items)
    251 right, 9 wrong
    121 caught, 9 missed, 0 false alarms, 130 correctly allowed
    Accuracy 0.97, Precision 1.00, Recall 0.93, F1 0.96

  Before the 13 November improvements: 179 right, 81 missed, Recall 0.38.

  Saved report (eval/results/latest/report.md, 122 test items)
    118 right, 4 wrong. Precision 1.000, Recall 0.934, F1 0.966
    By kind: email 73/76, PDF 15/16, pasted text 9/10, links 30/30
    Threshold 60 was chosen on the dev split (dev F1 0.974), not on the test split.

  ML yardstick (TF-IDF + logistic regression, a measuring tool in the eval folder only)
    F1 0.948 on attack types it has seen, 0.635 on types it has never seen. The rules on
    the same 58 items: 0.980. The rules don't memorise templates.

  Generalisation check (16 hand-written emails outside the dataset, 8 scams and 8 genuine,
  including Chinese and Indonesian): 16 of 16 right. A small set written by the team; treat
  it as an indication only.

  Honest note: the 13 November rules were designed after reviewing the misses on the whole
  dataset (dev and test). So the test number above is no longer a "never seen" number for
  those rules. The rules are written from scam mechanics, not from dataset sentences, and the
  only truly held-out check is the 16 hand-written emails. Treat the test number as an upper
  bound until new data is added.

  The nine still missed, and why:
    6  "Your housing assignment is ready, kindly complete the form": asks for no password,
       money or details; the sender passes DMARC; the link is on its own domain. Nothing in
       the text can be proven. This is meaning, Gemini's territory.
    1  Pasted text showing the real microsoft.com address; the malicious link was behind
       "click here" and was lost in pasting.
    1  Pasted text with a dangerous attachment; attachments don't survive pasting.
    1  Link campus-careers-hub.com/apply: a neutral domain with no sign at all.

6D. TERMS

  TP caught, FN missed, FP false alarm, TN correctly allowed.
  Accuracy    (TP + TN) / all        Precision   TP / (TP + FP)
  Recall      TP / (TP + FN)         F1          2 x P x R / (P + R)
  With 260 items: Precision = 121 / (121 + 0) = 1.00. Recall = 121 / (121 + 9) = 0.93.
  For students, an FN (a scam let through) is the most dangerous mistake.

6E. WHAT YOU CAN AND CANNOT SAY

  Can      "On 260 synthetic items the rule engine caught 93 percent of scams with zero false
            alarms, and beat the ML yardstick on attack types it had never seen."
  Can      "The AI layer is built in and can be measured with the same command."
  Cannot   "Our AI is X percent accurate." (not measured)
  Cannot   "It has been tested on real phishing." (it hasn't)


7. THE AI LAYER (GEMINI): WHAT CHANGES WHEN IT IS ON
--------------------------------------------------------------------------------------------

7A. TURNING IT ON

  Copy .env.example to .env, fill in GEMINI_API_KEY, restart the server. The chip at the top
  right changes to "AI reasoning: on". One key covers Scan, Analyst and Evaluation. The key
  never reaches the browser. Full steps in SETUP.md.

7B. WHAT CHANGES AND WHAT DOESN'T

    Part                                Without key         With key
    ----------------------------------  ------------------  --------------------------------
    Sender check                        code                code (same)
    Link scan                           code                code (same)
    Campaign memory                     code                code (same)
    Scam scripts and minimum scores     code                code (same)
    Wording component                   keyword rules       Gemini (max 35)
    Evidence sentences                  pattern matching    Gemini, checked against the email
    Main finding on the card            template            Gemini
    Final score                         the sum             the higher of the sum and
                                                            Gemini's own final score
    Link label and score                code                code (same)
    Link explanation                    template            Gemini rewrites the sentences

  Gemini receives: the output of all four tools (including the scam scripts matched), both
  playbooks, and the email wrapped as "untrusted data". It scores the wording part, quotes
  sentences, and gives its own final score.

  Gemini can RAISE the score, never lower it below the rule engine's sum. The minimum scores
  for scam scripts, executable attachments and prompt injection still apply. So AI mode is
  never weaker than rule mode on technical signs.

  What Gemini is for: the remainder the rules can't reach, which is meaning. Examples: the
  polite "housing assignment" form, emails in Chinese or Indonesian, wordings that aren't in
  any keyword list.

7C. SAFEGUARDS

  Quotes are checked    every Gemini quote is looked up in the email text; missing ones are
                        struck through and a "found in the email" percentage is shown
  Can't fail silently   missing, rejected or rate-limited key, over 30 seconds, or a
                        malformed answer: the rules take over, an amber note gives the
                        reason, Analyst logs LLM_FALLBACK
  Prompt injection      the email is marked as data, not instructions; an attempt to
                        command the AI ("ignore previous instructions") forces at least 88
  Time limits           20 seconds per attempt, 30 in total; rate limits retried; first
                        model gemini-3-flash-preview, fallback gemini-2.5-flash

  Tested with a fake key: Google answers "API key not valid" and the app switches to the
  rules in under a second. The amber note is still technical for now ("400
  INVALID_ARGUMENT").

7D. COST AND PRIVACY

  One call per email/PDF scan, one per link scan (explanation only), one per evaluation item
  when "Use Gemini" is ticked. With the AI on, the email is sent to Google; use sample
  emails, not real students' mail.

7E. MEASURING THE AI

  Run eval\run_eval.py with the key in place. The llm_hybrid (rules + Gemini) and llm_only
  rows fill in report.md on the same 132 test items. Answers are cached, so a daily limit can
  be continued the next day. Until that is done, the AI's accuracy is unmeasured.


8. CAMPAIGN MEMORY AND PRIVACY
--------------------------------------------------------------------------------------------

  - The file campaign_memory.db in the project folder.
  - Only HIGH or CRITICAL results are remembered. Ordinary mail leaves no trace.
  - Only the attacker's side is kept: sender domain, subject pattern (digits replaced by #),
    and a fingerprint (hash) of sender, subject and link domains. The body, the full sender
    address and the recipients are not stored.
  - The same pattern again: +15. Example: the scholarship PDF goes from 75 (Suspicious
    email) to 90 (Likely scam) on the second scan.
  - The Campaign memory panel on Analyst starts with one demo campaign (paypai-support.com).
    It doesn't match the PayPal sample exactly, so a first scan still gets +0; to show the
    +15, scan the same email twice.
  - The Evaluation tab doesn't write to memory.
  - To restart a demo from scratch: stop the server, delete campaign_memory.db, start again.
  - Items added on Evaluation are stored in eval/added/ and never pushed to GitHub.


9. LIMITS WE MUST ADMIT
--------------------------------------------------------------------------------------------

  - The evaluation data is synthetic. Not tested on real phishing. The generalisation check
    is only 16 emails the team wrote, and the latest rules were designed after reviewing
    errors on the whole dataset (see 6C).
  - The AI layer has not been measured with real Gemini, only tested with mock answers.
  - The rules are blind to meaning: a polite deceptive invitation that asks for nothing
    gets through.
  - Rule keywords are English only; other languages are judged by sender and links.
  - PDFs carry no headers; pasted text loses hidden links and attachments.
  - An "are you available?" opener from a real friend that happens to match the script will
    be flagged Suspicious. The advice given is: phone the person.
  - Shortened links are not followed; every shortened link counts as suspicious.
  - The university list was compiled from general knowledge; check the domains that matter
    to you on the universities' official sites. Unlisted universities are still protected
    by the generic lookalike rules and the "recipient's own university" rule.


10. QUESTIONS JUDGES MIGHT ASK
--------------------------------------------------------------------------------------------

"Where is the AI?"
  Gemini reads the message, judges how it manipulates the reader, and explains with quotes.
  Around it an agent runs the sender, link, memory and scam-script tools. Without a key the
  Gemini part is replaced by keyword rules, and the app says so.

"If the rules already hit 93 percent, why Gemini?"
  The remaining 7 percent are polite scams with no explicit request, plus languages other
  than English. That is meaning, which can't be written as keywords. Gemini is in place for
  it, and the measurement is ready.

"What if Gemini makes things up?"
  Quotes are checked against the email; missing ones are struck through. Gemini can't lower
  the tools' score, and the minimum scores still apply.

"What if the email contains instructions meant to trick the AI?"
  The email is handed over as data, not instructions. A detected prompt-injection attempt
  forces at least 88.

"How do you know the rules aren't just memorising the dataset?"
  Three things: the rules are written from scam mechanics (gift cards, release fees, bank
  changes), not from dataset sentences; the ML model that memorises templates drops to F1
  0.635 on new attack types while the rules score 0.980; and 16 hand-written emails outside
  the dataset, including Chinese and Indonesian, came out 16 right.

"Why no false alarms?"
  Because the rules are built on verification: a proven sender (real university or trusted
  list, DMARC pass) linking to its own domain never gets a minimum score, however urgent the
  wording. Minimum scores only apply when the sender or the link can't be vouched for.

"Where does the data come from?"
  Synthetic, generated with a fixed seed. The five fictional universities are deliberately
  kept off the trusted list so nothing favours the rules.

"What do you store from my email?"
  Ordinary email isn't stored. For scams, only the attacker's domain and subject pattern.
