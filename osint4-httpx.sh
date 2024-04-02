#!/bin/bash

# Check if the target domain is provided as an argument
if [ -z "$1" ]; then
    echo "Usage: $0 -t <target_domain>"
    exit 1
fi

# Parse command-line options using getopts
while getopts "t:" opt; do
    case $opt in
        t)
            TARGET="$OPTARG"   # Set the target domain
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            exit 1
            ;;
    esac
done

# Check if the target domain is provided
if [ -z "$TARGET" ]; then
    echo "Usage: $0 -t <target_domain>"
    exit 1
fi

# Define script variables
WORKING_DIR="$(cd "$(dirname "$0")" && pwd -P)"
OUTPUT_DIR="$WORKING_DIR/output/$TARGET"  # Create a subfolder for each domain
WORDLIST_PATH="$WORKING_DIR/wordlists"
AMASS_PATH="$HOME/go/bin/amass"
SUBFINDER_PATH="$HOME/go/bin/subfinder"
PUREDNS_PATH="/root/go/bin/puredns"
AMASS_OUTPUT="$OUTPUT_DIR/amass_output.txt"
SUBFINDER_OUTPUT="$OUTPUT_DIR/subfinder_output.txt"
DNSRECON_OUTPUT="$OUTPUT_DIR/dnsrecon_output.xml"
ALL_OUTPUT="$OUTPUT_DIR/all_output.txt"
UPDATED_WORDLIST="$OUTPUT_DIR/updated_wordlist.txt"
DNSRECON_RESULTS="$OUTPUT_DIR/dnsrecon_results.txt"
CUSTOM_WORDLIST="/opt/test/light-dns-recon2.txt"
HTTPX_PATH="/root/go/bin/httpx"
HTTPX_OUTPUT="$OUTPUT_DIR/valid_domain_httpx.txt"

RED="\033[1;31m"
GREEN="\033[1;32m"
BLUE="\033[1;36m"
RESET="\033[0m"

# Function to run Amass
runAmass(){
    echo -e "${BLUE}--==[ Running Amass ]==--${RESET}"
    "$AMASS_PATH" enum -passive -d "$TARGET" -o "$AMASS_OUTPUT" >/dev/null 2>&1
    echo -e "${GREEN}[+] Amass completed.${RESET}"
}

# Function to run Subfinder
runSubfinder(){
    echo -e "${BLUE}--==[ Running Subfinder ]==--${RESET}"
    "$SUBFINDER_PATH" -d "$TARGET" -t 10 -nW --silent -o "$SUBFINDER_OUTPUT" >/dev/null 2>&1
    echo -e "${GREEN}[+] Subfinder completed.${RESET}"
}

# Function to run DNSRecon
runDnsRecon(){
    echo -e "${BLUE}--==[ Running DNSRecon ]==--${RESET}"
    dnsrecon -d "$TARGET" -D "$CUSTOM_WORDLIST" -t brt --xml "$DNSRECON_OUTPUT" >/dev/null 2>&1
    echo -e "${GREEN}[+] DNSRecon completed.${RESET}"
}

# Function to resolve valid domains using puredns
runPureDNS(){
    echo -e "${BLUE}--==[ Running PureDNS to resolve valid domains ]==--${RESET}"
    
    # Run puredns resolve on the updated wordlist, sort the output, and store it
    "$PUREDNS_PATH" resolve "$UPDATED_WORDLIST" | sort > "$OUTPUT_DIR/valid_domains.txt"
    echo -e "${GREEN}[+] PureDNS completed.${RESET}"
}

# Function to run httpx for HTTP probing
runHttpx(){
    echo -e "${BLUE}--==[ Running httpx for HTTP probing ]==--${RESET}"
    "$HTTPX_PATH" -l "$UPDATED_WORDLIST" -title -tech-detect -status-code -o "$HTTPX_OUTPUT" >/dev/null 2>&1
    echo -e "${GREEN}[+] httpx completed.${RESET}"
}

# Function to compare results and create an updated wordlist
compareResults(){
    echo -e "${BLUE}--==[ Comparing Amass, Subfinder, DNSRecon, and httpx results ]==--${RESET}"

    # Combine Amass, Subfinder, and DNSRecon outputs into a single file, stripping "www" prefix
    cat "$AMASS_OUTPUT" "$SUBFINDER_OUTPUT" <(xmlstarlet sel -t -v "//dnsa" -n "$DNSRECON_OUTPUT" 2>/dev/null) | sed 's/^www\.//' > "$UPDATED_WORDLIST"

    # Add httpx results to the updated wordlist
    cat "$UPDATED_WORDLIST" "$HTTPX_OUTPUT" | sort -u > "$UPDATED_WORDLIST.tmp"
    mv "$UPDATED_WORDLIST.tmp" "$UPDATED_WORDLIST"

    echo -e "${GREEN}[+] Comparison completed.${RESET}"
}

# Function to store results in the specified output files
storeResults(){
    echo -e "${BLUE}--==[ Storing scan results ]==--${RESET}"

    # Separate the unique list of domain names and DNSRecon results
    awk '!/^$/' RS= ORS="\n\n" "$UPDATED_WORDLIST" > "$ALL_OUTPUT"
    
    # Store the unique list of domain names resolved by PureDNS in the specified output file
    echo -e "${BLUE}--==[ Storing domains resolved by PureDNS ]==--${RESET}"
    comm -12 <(sort "$UPDATED_WORDLIST") <(sort "$OUTPUT_DIR/valid_domains.txt") > "$OUTPUT_DIR/domains_resolved_by_puredns.txt"

    echo -e "${GREEN}[+] Storage completed.${RESET}"
}

# Function to display summary
displaySummary(){
    echo -e "\n${BLUE}--==[ Summary ]==--${RESET}"

    # Calculate the number of identified domains
    IDENTIFIED_DOMAINS=$(wc -l < "$UPDATED_WORDLIST")
    echo -e "${GREEN}[+] Number of identified domains: $IDENTIFIED_DOMAINS${RESET}"

    # Calculate and display the time needed to complete the scan in minutes
    END_TIME=$(date +%s)
    ELAPSED_TIME=$((END_TIME - START_TIME))
    ELAPSED_MINUTES=$((ELAPSED_TIME / 60))
    echo -e "${GREEN}[+] Time needed to complete the scan: $ELAPSED_MINUTES minutes${RESET}"

    # Display the number of resolved valid domains using PureDNS
    VALID_DOMAINS=$(wc -l < "$OUTPUT_DIR/valid_domains.txt")
    echo -e "${GREEN}[+] Number of resolved valid domains: $VALID_DOMAINS${RESET}"
}

# Function to find new domains
findNewDomains(){
    echo -e "${BLUE}--==[ Finding new domains ]==--${RESET}"

    # Sort and make sure both files are formatted identically
    sort "$PREVIOUS_OUTPUT_FILE" -o "$PREVIOUS_OUTPUT_FILE"
    sort "$OUTPUT_DIR/valid_domains.txt" -o "$OUTPUT_DIR/valid_domains.txt"

    # Find the difference between the current and previous scans
    new_domains=$(comm -13 "$PREVIOUS_OUTPUT_FILE" "$OUTPUT_DIR/valid_domains.txt")

    # Print new domains
}

# Main function
main(){
    echo -e "${BLUE}--==[ OSINT script to discover company assets ]==--${RESET}"

    # Create the output directory for the current domain
    mkdir -p "$OUTPUT_DIR" "$WORDLIST_PATH"

    # Record the start time
    START_TIME=$(date +%s)

    # Run Amass, Subfinder, and DNSRecon
    runAmass
    runSubfinder
    runDnsRecon

    # Compare results and create an updated wordlist
    compareResults

    # Run PureDNS to resolve valid domains
    runPureDNS

    # Run httpx for HTTP probing
    runHttpx

    # Store results in the specified output files
    storeResults

    # Display summary
    displaySummary

    echo -e "${GREEN}--==[ Script execution completed ]==--${RESET}"
}

# Run the main function
main
