import os
import json
import random
import argparse
from pathlib import Path
from datetime import datetime, timezone
import requests
from requests_oauthlib import OAuth1

BASE_DIR = Path(__file__).resolve().parent.parent.parent
ENV_PATH = BASE_DIR / ".env.twitter"
TWEETS_PATH = Path(__file__).resolve().parent / "tweets.json"
POSTED_HISTORY_PATH = Path(__file__).resolve().parent / "posted_history.json"


def load_env():
    """Load credentials from .env.twitter."""
    if not ENV_PATH.exists():
        raise FileNotFoundError(f"Missing {ENV_PATH}. Please provide Twitter API credentials.")
    
    env = {}
    with open(ENV_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


def get_oauth_session():
    """Build OAuth1 session using user context credentials."""
    env = load_env()
    api_key = env.get("TWITTER_API_KEY")
    api_secret = env.get("TWITTER_API_SECRET")
    access_token = env.get("TWITTER_ACCESS_TOKEN")
    access_token_secret = env.get("TWITTER_ACCESS_TOKEN_SECRET")

    if not all([api_key, api_secret, access_token, access_token_secret]):
        raise ValueError("Incomplete OAuth1 credentials in .env.twitter")

    auth = OAuth1(
        api_key,
        client_secret=api_secret,
        resource_owner_key=access_token,
        resource_owner_secret=access_token_secret,
    )
    return auth


def load_tweets():
    """Load tweets list."""
    if not TWEETS_PATH.exists():
        raise FileNotFoundError(f"Missing tweets bank: {TWEETS_PATH}")
    with open(TWEETS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_tweets(tweets_data):
    """Save updated tweets list with indentation."""
    with open(TWEETS_PATH, "w", encoding="utf-8") as f:
        json.dump(tweets_data, f, ensure_ascii=False, indent=2)


def get_next_tweet(tweets_data, category=None):
    """Select the first unposted tweet, optionally filtered by category."""
    candidates = [t for t in tweets_data if not t.get("posted")]
    if category:
        filtered = [t for t in candidates if t.get("category") == category]
        if filtered:
            candidates = filtered
    if not candidates:
        return None
    return candidates[0]


def post_tweet(text: str, auth) -> dict:
    """Post tweet using Twitter API v2 endpoints."""
    url = "https://api.twitter.com/2/tweets"
    payload = {"text": text}
    headers = {"Content-Type": "application/json"}
    
    resp = requests.post(url, auth=auth, json=payload, headers=headers, timeout=15)
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"X API Error ({resp.status_code}): {resp.text}")
    return resp.json()


def verify_account(auth):
    """Verify authenticated user identity."""
    url = "https://api.twitter.com/2/users/me"
    resp = requests.get(url, auth=auth, timeout=15)
    if resp.status_code == 200:
        return resp.json().get("data", {})
    return {"error": resp.status_code, "msg": resp.text}


def main():
    parser = argparse.ArgumentParser(description="Envshield Autonomous X (Twitter) Agent")
    parser.add_argument("--post", action="store_true", help="Post the next unposted tweet to X")
    parser.add_argument("--dry-run", action="store_true", help="Preview the next tweet without posting")
    parser.add_argument("--verify", action="store_true", help="Verify credentials and account connection")
    parser.add_argument("--id", type=int, help="Post a specific tweet by ID")
    parser.add_argument("--custom", type=str, help="Post custom text immediately")
    parser.add_argument("--stats", action="store_true", help="Show posting bank statistics")
    args = parser.parse_args()

    auth = get_oauth_session()

    if args.verify:
        print("[*] Verifying X (Twitter) authentication...")
        user_info = verify_account(auth)
        if "id" in user_info:
            print(f"[✓] Connected successfully as @{user_info.get('username')} (Name: {user_info.get('name')}, ID: {user_info.get('id')})")
        else:
            print(f"[!] Verification failed: {user_info}")
        return

    tweets_data = load_tweets()
    unposted = [t for t in tweets_data if not t.get("posted")]
    posted = [t for t in tweets_data if t.get("posted")]

    if args.stats:
        print(f"Total tweets in bank: {len(tweets_data)}")
        print(f"Posted: {len(posted)}")
        print(f"Remaining: {len(unposted)}")
        return

    if args.custom:
        target_text = args.custom
        print(f"[*] Posting custom text: {target_text}")
        if args.dry_run:
            print("[DRY-RUN] Tweet not posted.")
            return
        res = post_tweet(target_text, auth)
        print(f"[✓] Posted successfully! Tweet ID: {res.get('data', {}).get('id')}")
        return

    target = None
    if args.id:
        matches = [t for t in tweets_data if t.get("id") == args.id]
        if not matches:
            print(f"[!] Tweet with ID {args.id} not found.")
            return
        target = matches[0]
    else:
        target = get_next_tweet(tweets_data)

    if not target:
        print("[!] No unposted tweets remaining in bank!")
        return

    print("=" * 60)
    print(f"Selected Tweet ID: #{target.get('id')} [{target.get('category')}]")
    print("-" * 60)
    print(target.get("text"))
    print("=" * 60)

    if args.dry_run or (not args.post and not args.id):
        print("\n[DRY RUN] Run with --post to publish this tweet to X.")
        return

    print("\n[*] Publishing to X...")
    try:
        res = post_tweet(target.get("text"), auth)
        tweet_id = res.get("data", {}).get("id")
        now_iso = datetime.now(timezone.utc).isoformat()
        
        target["posted"] = True
        target["posted_at"] = now_iso
        target["tweet_id"] = tweet_id
        save_tweets(tweets_data)
        
        print(f"[✓] Published successfully!")
        print(f"    URL: https://x.com/i/status/{tweet_id}")
        print(f"    Remaining unposted: {len(unposted) - 1}")
    except Exception as e:
        print(f"[!] Failed to post tweet: {e}")


if __name__ == "__main__":
    main()
