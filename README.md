# tia-ti-DomainAgeChecker
Queries the WHOIS database to determine the age of a domain. Can identify newly registered domains which may be associated with malicious activity.

## Install
`git clone https://github.com/ShadowGuard-AI/tia-ti-domainagechecker`

## Usage
`python3 main.py example.com`
`python3 main.py example.com -o results.txt`

## Parameters
- `domain`: The domain name to check (required positional argument).
- `-h`: Show help message and exit
- `-v`: Enable verbose output (debug logging).
- `-o`: Output file to save results to (optional).
- `--timeout`: Timeout in seconds for the WHOIS query (default: 30). Must be positive; a zero or negative value is a usage error and exits 2.

## Notes
The domain must match a strict domain pattern; invalid input is rejected and exits 1 before any query is made. Creation dates returned as strings (ISO form, or `YYYY-MM-DD HH:MM:SS`, or `YYYY-MM-DD`) are parsed the same way as datetime values, and when the record lists several creation dates the earliest is used. A registration date in the future is invalid data: the tool reports it as an error and exits non-zero instead of printing a negative age. Timezone-aware registration dates are converted to UTC before the age is computed. Lookup failures exit non-zero with no age verdict. If an output file is requested and cannot be written, the tool exits 1.

## License
MIT License. See LICENSE.
