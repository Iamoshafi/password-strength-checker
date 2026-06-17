import re
import math


# Common weak/breached passwords - a small sample
# NIST 800-63B's strongest recommendation: check against known breached passwords
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "letmein", "dragon", "111111", "baseball",
    "iloveyou", "trustno1", "sunshine", "master", "welcome",
    "shadow", "ashley", "football", "jesus", "michael",
    "ninja", "mustang", "password1", "123456789", "admin"
}


def check_breached(password):
    """
    NIST 800-63B's primary recommendation: reject passwords found in
    known breach/common password lists, rather than enforcing complexity.
    """
    return password.lower() in COMMON_PASSWORDS


def check_minimum_length(password):
    """
    NIST 800-63B requires a minimum of 8 characters, and recommends
    allowing/encouraging up to 64 characters. Longer is better.
    """
    length = len(password)
    if length < 8:
        return False, f"Fails NIST minimum (8 characters required, got {length})"
    elif length < 15:
        return True, f"Meets NIST minimum, but below recommended 15+ characters"
    else:
        return True, f"Meets NIST recommended length (15+ characters)"


def check_all_numeric(password):
    """NIST flags purely numeric passwords (like PINs) as weak."""
    return password.isdigit()


def check_repetitive(password):
    """
    NIST recommends rejecting passwords with excessive repetition
    or simple sequences, as these reduce effective entropy.
    """
    issues = []
    if re.search(r'(.)\1{2,}', password):
        issues.append("Contains repeated characters (e.g. 'aaa')")
    if re.search(r'(0123|1234|2345|3456|4567|5678|6789)', password):
        issues.append("Contains sequential numbers")
    return issues


def get_character_info(password):
    """
    Informational only - NIST no longer requires character variety,
    but we display this for transparency/education.
    """
    return {
        'lowercase': bool(re.search(r'[a-z]', password)),
        'uppercase': bool(re.search(r'[A-Z]', password)),
        'digit': bool(re.search(r'\d', password)),
        'symbol': bool(re.search(r'[^a-zA-Z0-9]', password))
    }


def calculate_entropy(password):
    """
    Entropy in bits - reflects NIST's actual concern: how random/
    unpredictable is this password, regardless of character rules.
    """
    char_info = get_character_info(password)
    pool_size = 0
    if char_info['lowercase']:
        pool_size += 26
    if char_info['uppercase']:
        pool_size += 26
    if char_info['digit']:
        pool_size += 10
    if char_info['symbol']:
        pool_size += 32

    if pool_size == 0:
        return 0

    return round(len(password) * math.log2(pool_size), 2)


def estimate_crack_time(entropy_bits):
    """Estimate brute-force crack time at 10 billion guesses/second."""
    guesses_per_second = 10_000_000_000
    total_combinations = 2 ** entropy_bits
    seconds = total_combinations / guesses_per_second

    if seconds < 1:
        return "Instantly"
    elif seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.1f} days"
    else:
        years = seconds / 31536000
        return "Millions of years" if years > 1_000_000 else f"{years:,.0f} years"


def analyze_password(password):
    """Run NIST 800-63B aligned analysis and print a report."""
    print(f"\n{'='*55}")
    print(f"NIST SP 800-63B Password Analysis")
    print(f"{'='*55}")

    # Step 1: Breach check - NIST's top priority
    if check_breached(password):
        print("\n❌ REJECTED: This password appears in known breach lists.")
        print("NIST 800-63B requires rejecting breached/common passwords")
        print("regardless of length or complexity.")
        print(f"{'='*55}\n")
        return

    # Step 2: Minimum length
    length_ok, length_msg = check_minimum_length(password)
    if not length_ok:
        print(f"\n❌ REJECTED: {length_msg}")
        print(f"{'='*55}\n")
        return
    print(f"\n✓ Length: {length_msg}")

    # Step 3: All-numeric check
    if check_all_numeric(password):
        print("\n⚠️  WARNING: Purely numeric passwords are considered weak under NIST guidance.")

    # Step 4: Repetition/sequence check
    issues = check_repetitive(password)
    if issues:
        print("\n⚠️  Reduced entropy detected:")
        for issue in issues:
            print(f"   - {issue}")
    else:
        print("\n✓ No repetitive or sequential patterns detected")

    # Step 5: Character composition (informational only, not scored)
    char_info = get_character_info(password)
    print(f"\nCharacter composition (informational - not a NIST requirement):")
    for char_type, present in char_info.items():
        symbol = "✓" if present else "—"
        print(f"   {symbol} {char_type}")

    # Step 6: Entropy and crack time
    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)
    print(f"\nEntropy: {entropy} bits")
    print(f"Estimated brute-force crack time: {crack_time}")

    # Final verdict - based on NIST's actual priorities: passed breach 
    # check, met length, low entropy concerns
    print(f"\n{'-'*55}")
    if entropy < 40:
        print("VERDICT: Weak — low entropy, vulnerable to brute force")
    elif entropy < 60:
        print("VERDICT: Acceptable — meets NIST minimums")
    elif entropy < 80:
        print("VERDICT: Strong")
    else:
        print("VERDICT: Excellent")
    print(f"{'='*55}\n")


if __name__ == "__main__":
    test_password = input("Enter a password to analyze: ")
    analyze_password(test_password)