import secrets

def generate_seed_phrase(wordlist_file="english.txt", num_words=24):
    """
    Generates a seed phrase by randomly selecting words from a wordlist file.

    Args:
        wordlist_file (str): The path to the file containing the wordlist
                             (one word per line).  Defaults to "english.txt".
        num_words (int): The number of words in the seed phrase. Defaults to 24.

    Returns:
        str: A string containing the seed phrase, or None if an error occurs.
    """
    try:
        with open(wordlist_file, "r") as f:
            words = [line.strip() for line in f]  # Read words, remove newlines

        if not words:
            print(f"Error: Wordlist file '{wordlist_file}' is empty.")
            return None

        if len(words) < num_words:
            print(f"Error: Wordlist contains fewer than {num_words} words.")
            return None

        # Use secrets.choice for cryptographically secure random choice
        seed_phrase_words = [secrets.choice(words) for _ in range(num_words)]
        seed_phrase = " ".join(seed_phrase_words)

        return seed_phrase

    except FileNotFoundError:
        print(f"Error: Wordlist file '{wordlist_file}' not found.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


if __name__ == "__main__":
    seed_phrase = generate_seed_phrase()  # Uses default wordlist and length
    if seed_phrase:
        print(seed_phrase)
