# Fixture: hardcoded secrets. Three lines should be flagged. The variables below
# deliberately keep "password"/"api_key" in their NAMES so that the placeholder
# guards in the rule are genuinely exercised rather than bypassed.
import os

API_KEY = "sk_live_9f8a7b6c5d4e3f2a1b0c"
DB_PASSWORD = "Spr1ng2024!prod"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

# Safe: read from the environment at runtime.
SAFE_KEY = os.environ["API_KEY"]
SAFE_PASSWORD = os.getenv("DB_PASSWORD")

# Safe: values that are obviously placeholders, docs, masks, or too short.
PLACEHOLDER_PASSWORD = "changeme"
DOC_SLOT_API_KEY = "<YOUR_API_KEY>"
MASKED_PASSWORD = "xxxxxxxxxx"
SHORT_PASSWORD = "abc"


def authorize():
    # The key itself is a variable reference here, not a literal.
    return {"Authorization": API_KEY}
