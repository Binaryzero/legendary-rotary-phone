import os

import emoji


def remove_emojis(text):
    return emoji.replace_emoji(text, replace="")


def sanitize_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        sanitized = remove_emojis(content)
        if content != sanitized:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(sanitized)
            print(f"Sanitized: {filepath}")
            return True
    except Exception:
        # Likely a binary file or unreadable, skip it
        pass
    return False


changed = False
for root, dirs, files in os.walk("."):
    # Skip .git and workflow directories
    if ".git" in root or root.startswith("./.github"):
        continue
    for file in files:
        full_path = os.path.join(root, file)
        if sanitize_file(full_path):
            changed = True

if not changed:
    print("✅ No emojis found.")
else:
    print("✅ Emojis sanitized and files updated.")
