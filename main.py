import argparse
import logging
import whois
import datetime
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
            creation_date = w.creation_date
            if isinstance(creation_date, list): # Handle multiple creation dates, taking the earliest.
              # Taking the earliest of several reported dates is the conservative choice for spotting new domains, since a registrar that reports both a transfer date and the original registration would otherwise make an old name look fresh. An earlier version carried a second list branch below this line that could never run, because min has already reduced the list to one value; that dead branch was removed with the future date fix.
              creation_date = min(creation_date)

            if not isinstance(creation_date, datetime.datetime):
                logging.warning(f"Unexpected creation_date type: {type(creation_date)}. Attempting conversion.")
                try:
                    creation_date = datetime.datetime.strptime(str(creation_date), '%Y-%m-%d %H:%M:%S')
                except (ValueError, TypeError):
                    try:
                         creation_date = datetime.datetime.strptime(str(creation_date).split(' ')[0], '%Y-%m-%d')
                    except (ValueError, TypeError):
                        logging.error(f"Could not convert creation_date: {creation_date}")
                        return None, None

            if creation_date.tzinfo is not None:
                creation_date = creation_date.astimezone(datetime.timezone.utc).replace(tzinfo=None)

            if creation_date > datetime.datetime.now():
                logging.error(f"Invalid WHOIS data for {domain}: registration date {creation_date} is in the future.")
                return None, None

            # now() here is naive local time, which is safe at this point: aware creation dates are converted to naive UTC above, and a future creation date has already been rejected above as invalid data instead of yielding a negative age.
            age_in_days = (datetime.datetime.now() - creation_date).days
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

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    domain = args.domain

    # Input validation
    if not isinstance(domain, str) or not domain:
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
            # A failed save is logged and nothing else happens: the results are already on screen, the process exits 0, and the caller who asked for a file has no file. The exit code only ever reports whether the lookup worked, never whether the output landed.
            except IOError as e:
                logging.error(f"Error writing to file {args.output}: {e}")
    else:
        logging.error(f"Could not determine the age of the domain: {domain}")
        sys.exit(1)

# Example usage (only executed when the script is run directly)
if __name__ == "__main__":
    main()