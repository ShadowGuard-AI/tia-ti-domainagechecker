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
    return parser

def get_domain_age(domain):
    """
    Queries the WHOIS database and calculates the age of the domain.

    Args:
        domain (str): The domain name to check.

    Returns:
        tuple: A tuple containing the registration date (datetime object or None) and the domain age in days (int or None).
               Returns (None, None) if there's an error.
    """
    try:
        w = whois.whois(domain)

        if w.creation_date:
            creation_date = w.creation_date
            if isinstance(creation_date, list): # Handle multiple creation dates, taking the earliest.
              creation_date = min(creation_date)

            if not isinstance(creation_date, datetime.datetime):
                if isinstance(creation_date, list) and len(creation_date) > 0:
                    creation_date = creation_date[0] # take the first if list
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
    creation_date, age_in_days = get_domain_age(domain)

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
                logging.error(f"Error writing to file {args.output}: {e}")
    else:
        logging.error(f"Could not determine the age of the domain: {domain}")
        sys.exit(1)

# Example usage (only executed when the script is run directly)
if __name__ == "__main__":
    main()