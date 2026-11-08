import argparse
import logging
import re
import whois
import datetime
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DOMAIN_RE = re.compile(
    r'^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$'
)


def is_valid_domain(domain):
    """
    Validates the format of the input domain name against a strict
    domain pattern, rejecting spaces, URL syntax, and other non-domain
    input before any WHOIS query is made.
    """
    if not isinstance(domain, str) or not domain:
        return False
    return DOMAIN_RE.match(domain) is not None


def _parse_creation_date(value):
    """
    Converts a WHOIS creation date value to a datetime, or returns
    None when the value cannot be parsed. Accepts datetime objects
    and ISO or common registry string forms.
    """
    if isinstance(value, datetime.datetime):
        return value
    text = str(value).strip()
    try:
        return datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        pass
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d'):
        try:
            return datetime.datetime.strptime(text.split(' ')[0] if fmt == '%Y-%m-%d' else text, fmt)
        except (ValueError, TypeError):
            continue
    return None

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Queries the WHOIS database to determine the age of a domain. Can identify newly registered domains which may be associated with malicious activity.")
    parser.add_argument("domain", help="The domain name to check.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    parser.add_argument("-o", "--output", help="Output file to save results to (optional).", metavar="FILE")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout in seconds for the WHOIS query (default: 30).")
    return parser

def get_domain_age(domain, timeout=30):
    """
    Queries the WHOIS database and calculates the age of the domain.

    Args:
        domain (str): The domain name to check.

    Returns:
        tuple: A tuple containing the registration date (datetime object or None) and the domain age in days (int or None).
               Returns (None, None) if there's an error.
    """
    try:
        w = whois.whois(domain, timeout=timeout)

        if w.creation_date:
            # Handle multiple creation dates, taking the earliest.
            # Taking the earliest of several reported dates is the
            # conservative choice for spotting new domains, since a
            # registrar that reports both a transfer date and the
            # original registration would otherwise make an old name
            # look fresh. Each entry is parsed before the minimum is
            # taken, so string dates are handled the same way as
            # datetime dates.
            raw_dates = w.creation_date if isinstance(w.creation_date, list) else [w.creation_date]
            parsed_dates = []
            for raw in raw_dates:
                converted = _parse_creation_date(raw)
                if converted is None:
                    logging.error(f"Could not convert creation_date: {raw}")
                    return None, None
                parsed_dates.append(converted)
            creation_date = min(parsed_dates)

            if creation_date.tzinfo is not None:
                creation_date = creation_date.astimezone(datetime.timezone.utc).replace(tzinfo=None)

            # Aware creation dates are converted to naive UTC above, so
            # the comparison point is the current UTC time, not local
            # wall clock time. A future creation date is rejected above
            # as invalid data instead of yielding a negative age.
            now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            if creation_date > now:
                logging.error(f"Invalid WHOIS data for {domain}: registration date {creation_date} is in the future.")
                return None, None

            age_in_days = (now - creation_date).days
            return creation_date, age_in_days
        else:
            logging.warning(f"No creation date found for {domain}.")
            return None, None

    except whois.parser.PywhoisError as e:
        logging.error(f"WHOIS query failed for {domain}: {e}")
        return None, None
    except Exception as e:
        logging.exception(f"An unexpected error occurred while processing {domain}: {e}")
        return None, None


def main():
    """
    Main function to parse arguments, query WHOIS, and print results.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("--timeout must be a positive number of seconds.")

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    domain = args.domain

    # Input validation
    if not is_valid_domain(domain):
        logging.error("Invalid domain name. Please provide a valid domain.")
        sys.exit(1)


    logging.info(f"Checking domain age for: {domain}")
    creation_date, age_in_days = get_domain_age(domain, timeout=args.timeout)

    if creation_date and age_in_days is not None:
        print(f"Domain: {domain}")
        print(f"Registration Date: {creation_date}")
        print(f"Age (days): {age_in_days}")

        if args.output:
            try:
                with open(args.output, "w") as f:
                    f.write(f"Domain: {domain}\n")
                    f.write(f"Registration Date: {creation_date}\n")
                    f.write(f"Age (days): {age_in_days}\n")
                logging.info(f"Results saved to {args.output}")
            except IOError as e:
                # A failed save exits non-zero: the caller asked for a
                # file and has no file, so the run did not complete.
                logging.error(f"Error writing to file {args.output}: {e}")
                sys.exit(1)
    else:
        logging.error(f"Could not determine the age of the domain: {domain}")
        sys.exit(1)

# Example usage (only executed when the script is run directly)
if __name__ == "__main__":
    main()