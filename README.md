# tia-ti-DomainAgeChecker
Queries the WHOIS database to determine the age of a domain. Can identify newly registered domains which may be associated with malicious activity. - Focused on Aggregates threat intelligence data from various public sources (e.g., blogs, feeds, APIs) into a unified format for analysis. Extracts indicators of compromise (IOCs) and provides basic filtering and searching capabilities. Enables security teams to quickly identify and assess potential threats.

## Install
`git clone https://github.com/ShadowStrikeHQ/tia-ti-domainagechecker`

## Usage
`./tia-ti-domainagechecker [params]`

## Parameters
- `-h`: Show help message and exit
- `-v`: No description provided
- `-o`: Output file to save results to (optional).
- `--timeout`: Timeout in seconds for the WHOIS query (default: 30).

## Notes
A registration date in the future is invalid data: the tool reports it as an error and exits non-zero instead of printing a negative age. Timezone-aware registration dates are converted to UTC before the age is computed. Lookup failures already exit non-zero with no age verdict, and that behavior is unchanged.

## License
Copyright (c) ShadowStrikeHQ
