# python.py
import os

def main():
    # Fetch message from environment variable with a default fallback
    message = os.getenv("GZCTF_FLAG", "Flag")
    print(message)

if __name__ == "__main__":
    main()