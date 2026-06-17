# Password Strength Checker (NIST SP 800-63B Compliant)
A Python tool that analyzes password strength following the current 
NIST SP 800-63B guidelines — prioritizing length and breach-checking 
over arbitrary complexity rules.

## Why I built this
Most password checkers still enforce outdated rules: mandatory 
symbols, uppercase, numbers. NIST moved away from this years ago, 
but a lot of real-world systems haven't caught up. I built this 
to actually implement the current standard and understand why 
the shift happened.

## The key idea: length beats complexity

Most people assume a password like `P@ssw0rd1!` is strong because 
it has symbols, numbers, and mixed case. It isn't — it's short and 
follows a predictable pattern (capital letter, common word, number, 
symbol at the end) that attackers already expect.

A long passphrase like `correct horse battery staple` is actually 
much harder to crack, even though it's just lowercase words with 
spaces.

Here's why: every password has a property called **entropy** — 
basically, a measure of how many guesses an attacker would need 
to make before finding it by chance. The longer a password is, 
the faster entropy grows. Adding a few more characters does more 
to protect a password than swapping a letter for a symbol ever 
will.

This tool calculates that entropy directly and estimates how long 
a brute-force attack would actually take — so instead of just 
saying "weak" or "strong," it shows you the math behind why.

## What it checks
- **Breach/common password check** — rejects passwords found in 
  known breached password lists (NIST's top recommendation)
- **Minimum length** — 8 characters required, 15+ recommended
- **Entropy calculation** — measures randomness in bits
- **Estimated crack time** — how long a brute-force attack would 
  realistically take, based on entropy
- **Pattern detection** — flags repeated characters and 
  sequential numbers
- Character variety (uppercase/lowercase/numbers/symbols) is shown for information only — NIST no longer requires it, 
  so it isn't used to score the password

## Example output
NIST SP 800-63B Password Analysis
- ✓ Length: Meets NIST recommended length (15+ characters)
- ✓ No repetitive or sequential patterns detected
- Entropy: 94.3 bits
- Estimated brute-force crack time: Millions of years
- VERDICT: Excellent

## How to run it
pip install -r requirements.txt
python password_checker.py

## Limitations & future improvements
- Common password list is a small sample (25 entries) — a full 
  version would check against a real breached password database 
  like HaveIBeenPwned's API
- Doesn't account for dictionary words beyond the hardcoded list 
  (e.g. "Elephant123!" would score well on entropy despite being 
  a dictionary word with predictable capitalization)
- Next steps: integrate HaveIBeenPwned API for real breach 
  checking, add a passphrase generator feature
