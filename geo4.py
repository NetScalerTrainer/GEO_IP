#!/usr/bin/env python3
"""
Email Header IP Geolocation Analyzer (Interactive Version)

This script runs interactively and allows you to drag and drop .eml files
onto the terminal window for analysis. It extracts all 'Received:' headers,
finds IP addresses within them, and performs geolocation lookups.

Usage:
    python3 geo.py

Then drag and drop .eml files onto the terminal window when prompted.

Requirements:
    pip install requests

Author: Joseph Moses
"""

import sys
import email
import re
import requests
import json
import os
import codecs
from typing import List, Dict, Tuple, Optional
from email.message import EmailMessage


class EmailIPAnalyzer:
    def __init__(self):
        # Regex patterns for IPv4 and IPv6 addresses
        self.ipv4_pattern = re.compile(
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        )
        self.ipv6_pattern = re.compile(
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
            r'\b(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b|'
            r'\b::1\b|'
            r'\b::\b'
        )
        
        # Private/reserved IP ranges to filter out
        self.private_ipv4_patterns = [
            re.compile(r'^10\.'),
            re.compile(r'^192\.168\.'),
            re.compile(r'^172\.(1[6-9]|2[0-9]|3[01])\.'),
            re.compile(r'^127\.'),
            re.compile(r'^169\.254\.'),
            re.compile(r'^224\.'),
            re.compile(r'^240\.'),
        ]

    def load_eml_file(self, filepath: str) -> EmailMessage:
        """Load and parse an EML file."""
        try:
            with open(filepath, 'rb') as f:
                return email.message_from_bytes(f.read())
        except FileNotFoundError:
            print(f"Error: File '{filepath}' not found.")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file '{filepath}': {e}")
            sys.exit(1)

    def extract_received_headers(self, msg: EmailMessage) -> List[str]:
        """Extract all 'Received:' headers from the email."""
        received_headers = []
        
        # Get all 'Received' headers (there can be multiple)
        for header_name, header_value in msg.items():
            if header_name.lower() == 'received':
                received_headers.append(header_value)
        
        return received_headers

    def extract_ip_addresses(self, text: str) -> List[Tuple[str, str]]:
        """
        Extract IP addresses from text.
        Returns list of tuples: (ip_address, ip_type)
        """
        ips = []
        
        # Find IPv4 addresses
        ipv4_matches = self.ipv4_pattern.findall(text)
        for ip in ipv4_matches:
            if self.is_public_ipv4(ip):
                ips.append((ip, 'IPv4'))
        
        # Find IPv6 addresses
        ipv6_matches = self.ipv6_pattern.findall(text)
        for ip in ipv6_matches:
            if self.is_public_ipv6(ip):
                ips.append((ip, 'IPv6'))
        
        return ips

    def is_public_ipv4(self, ip: str) -> bool:
        """Check if IPv4 address is public (not private/reserved)."""
        for pattern in self.private_ipv4_patterns:
            if pattern.match(ip):
                return False
        return True

    def is_public_ipv6(self, ip: str) -> bool:
        """Check if IPv6 address is public (basic check)."""
        # Simple check for common private/local IPv6 addresses
        if ip.startswith('fe80:') or ip.startswith('fc') or ip.startswith('fd'):
            return False
        if ip == '::1' or ip == '::':
            return False
        return True

    def get_ip_geolocation(self, ip: str) -> Optional[Dict]:
        """
        Perform geolocation lookup for an IP address using ipinfo.io API.
        Falls back to ip-api.com if ipinfo.io fails.
        """
        # Try ipinfo.io first (more reliable, but has rate limits)
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'error' not in data:
                    return {
                        'service': 'ipinfo.io',
                        'ip': ip,
                        'city': data.get('city', 'Unknown'),
                        'region': data.get('region', 'Unknown'),
                        'country': data.get('country', 'Unknown'),
                        'location': data.get('loc', 'Unknown'),
                        'org': data.get('org', 'Unknown'),
                        'postal': data.get('postal', 'Unknown'),
                        'timezone': data.get('timezone', 'Unknown')
                    }
        except Exception as e:
            print(f"Warning: ipinfo.io lookup failed for {ip}: {e}")

        # Fallback to ip-api.com
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'service': 'ip-api.com',
                        'ip': ip,
                        'city': data.get('city', 'Unknown'),
                        'region': data.get('regionName', 'Unknown'),
                        'country': data.get('country', 'Unknown'),
                        'location': f"{data.get('lat', 'Unknown')},{data.get('lon', 'Unknown')}",
                        'org': data.get('isp', 'Unknown'),
                        'postal': data.get('zip', 'Unknown'),
                        'timezone': data.get('timezone', 'Unknown')
                    }
        except Exception as e:
            print(f"Warning: ip-api.com lookup failed for {ip}: {e}")

        return None

    def print_separator(self, char='=', length=80):
        """Print a separator line."""
        print(char * length)

    def print_results(self, results: List[Dict]):
        """Print the analysis results in a formatted way."""
        if not results:
            print("No public IP addresses found in Received headers.")
            return

        print(f"\nFound {len(results)} public IP address(es) in Received headers:\n")
        
        for i, result in enumerate(results, 1):
            self.print_separator('=')
            print(f"ENTRY #{i}")
            self.print_separator('=')
            
            print(f"\nRECEIVED HEADER:")
            print(f"{result['received_header']}\n")
            
            print(f"EXTRACTED IP: {result['ip']} ({result['ip_type']})")
            
            if result['geolocation']:
                geo = result['geolocation']
                print(f"\nGEOLOCATION INFO (via {geo['service']}):")
                print(f"  City:      {geo['city']}")
                print(f"  Region:    {geo['region']}")
                print(f"  Country:   {geo['country']}")
                print(f"  Location:  {geo['location']}")
                print(f"  ISP/Org:   {geo['org']}")
                print(f"  Postal:    {geo['postal']}")
                print(f"  Timezone:  {geo['timezone']}")
            else:
                print(f"\nGEOLOCATION INFO: Failed to retrieve")
            
            print()

    def clean_file_path(self, raw_path: str) -> str:
        """Clean up file path from drag-and-drop input."""
        # Remove surrounding quotes and whitespace
        file_path = raw_path.strip().strip('\'"')
        
        # Handle escaped characters using a simple approach
        # Replace common escape sequences
        replacements = [
            ('\\ ', ' '),      # escaped space
            ('\\[', '['),      # escaped opening bracket
            ('\\]', ']'),      # escaped closing bracket
            ('\\(', '('),      # escaped opening parenthesis
            ('\\)', ')'),      # escaped closing parenthesis
            ('\\#', '#'),      # escaped hash
            ('\\&', '&'),      # escaped ampersand
            ('\\$', '$'),      # escaped dollar sign
            ('\\%', '%'),      # escaped percent
            ('\\@', '@'),      # escaped at sign
            ('\\!', '!'),      # escaped exclamation
            ('\\^', '^'),      # escaped caret
            ('\\*', '*'),      # escaped asterisk
            ('\\+', '+'),      # escaped plus
            ('\\=', '='),      # escaped equals
            ('\\{', '{'),      # escaped opening brace
            ('\\}', '}'),      # escaped closing brace
            ('\\|', '|'),      # escaped pipe
            ('\\"', '"'),      # escaped quote
            ("\\'", "'"),      # escaped apostrophe
        ]
        
        for escaped, unescaped in replacements:
            file_path = file_path.replace(escaped, unescaped)
        
        # Handle escaped backslashes last to avoid conflicts
        file_path = file_path.replace('\\\\', '\\')
        
        return file_path

    def extract_common_headers(self, msg: EmailMessage) -> Dict[str, str]:
        """
        Extract common email headers and return their values.
        If a header is missing, returns 'n/a'.
        For 'Received', capture all occurrences.
        """
        email_indicators = [
            'Return-Path',
            'Received',
            'Message-ID',
            'Date',
            'From',
            'To',
            'Subject',
            'MIME-Version',
            'Content-Type'
        ]
        
        headers_found = {}

        for header in email_indicators:
            if header == "Received":
                # Collect all Received headers
                received_values = msg.get_all("Received")
                if received_values:
                    for i, value in enumerate(received_values, start=1):
                        headers_found[f"Received #{i}"] = value
                else:
                    headers_found["Received"] = "n/a"
            else:
                value = msg.get(header, "n/a")
                headers_found[header] = value
        
        return headers_found

    def print_common_headers(self, headers: Dict[str, str]):
        """Print common email headers in a formatted way."""
        print("\nCOMMON EMAIL HEADERS:")
        self.print_separator('-')
        for key, value in headers.items():
            print(f"{key}: {value}")
        self.print_separator('-')


    def print_common_headers(self, headers: Dict[str, str]):
        """Print common email headers in a formatted way."""
        print("\nCOMMON EMAIL HEADERS:")
        self.print_separator('-')
        for key, value in headers.items():
            print(f"{key}: {value}")
        self.print_separator('-')

    def analyze_eml_file(self, filepath: str):
        """Main method to analyze an EML file."""
        print(f"Analyzing EML file: {filepath}")
        print(f"Loading and parsing email...")
        
        # Load email
        msg = self.load_eml_file(filepath)
        
        # Extract and print common headers
        common_headers = self.extract_common_headers(msg)
        self.print_common_headers(common_headers)
        # Extract received headers
        received_headers = self.extract_received_headers(msg)
        
        if not received_headers:
            print("No 'Received:' headers found in the email.")
            return
        
        print(f"Found {len(received_headers)} 'Received:' header(s)")
        print("Extracting IP addresses and performing geolocation lookups...")
        
        results = []
        
        for header in received_headers:
            # Extract IP addresses from this header
            ips = self.extract_ip_addresses(header)
            
            for ip, ip_type in ips:
                print(f"  Looking up {ip}...")
                geolocation = self.get_ip_geolocation(ip)
                
                results.append({
                    'received_header': header.strip(),
                    'ip': ip,
                    'ip_type': ip_type,
                    'geolocation': geolocation
                })
        
        # Print results

        self.print_results(results)


def main():
    # Check if requests module is available
    try:
        import requests
    except ImportError:
        print("Error: 'requests' module is required.")
        print("Install it with: pip install requests")
        sys.exit(1)
    
    analyzer = EmailIPAnalyzer()
    
    print("=" * 60)
    print("   EMAIL HEADER IP GEOLOCATION ANALYZER")
    print("   by. Joseph Moses https://N90X.info")
    print("=" * 60)
    print()
    print("INSTRUCTIONS:")
    print("1. Drag and drop an .eml file onto this terminal window")
    print("2. Press Enter to analyze the file")
    print("3. Type 'quit' or 'exit' to close the program")
    print("4. Type 'clear' to clear the screen")
    print()
    print("TIP1: If drag-and-drop doesn't work, you can also type the full")
    print("     file path enclosed in quotes, like:")
    print('     "/Users/joseph/Desktop/email.eml"')
    print("TIP2: Drag and drop your email to desktop first.")
    print("     Then you can drag and drop this saved file onto")
    print('     this active terminal window.')
    print()
    print("Ready for input...")
    print()
    
    while True:
        try:
            # Get input from user
            user_input = input("Drop .eml file here (or 'quit' to exit): ").strip()
            
            # Handle special commands
            if user_input.lower() in ['quit', 'exit', 'q']:
                print("Goodbye!")
                break
            elif user_input.lower() in ['clear', 'cls']:
                os.system('cls' if os.name == 'nt' else 'clear')
                continue
            elif not user_input:
                continue
            
            # Clean up the file path
            file_path = analyzer.clean_file_path(user_input)
            
            # Check if file exists
            if not os.path.exists(file_path):
                print(f"Error: File not found: {file_path}")
                print()
                print("DEBUG INFO:")
                print(f"  Original input: {repr(user_input)}")
                print(f"  Processed path: {repr(file_path)}")
                print()
                print("TROUBLESHOOTING:")
                print("• Try enclosing the path in quotes when typing manually")
                print("• On macOS, you can also try: Cmd+Option+C to copy the path, then paste it here")
                print("• Make sure the file actually exists at that location")
                continue
            
            # Check if it's likely an eml file
            if not file_path.lower().endswith('.eml'):
                response = input(f"Warning: File doesn't end with .eml. Continue anyway? (y/n): ")
                if response.lower() not in ['y', 'yes']:
                    continue
            
            print("\n" + "="*60)
            print(f"Processing: {os.path.basename(file_path)}")
            print("="*60)
            
            # Analyze the file
            analyzer.analyze_eml_file(file_path)
            
            print("\n" + "="*60)
            print("Analysis complete! Drop another file or type 'quit' to exit.")
            print("="*60)
            print()
            
        except KeyboardInterrupt:
            print("\n\nProgram interrupted by user. Goodbye!")
            break
        except EOFError:
            print("\n\nProgram terminated. Goodbye!")
            break
        except Exception as e:
            print(f"An error occurred: {e}")
            print("Please try again or type 'quit' to exit.")
            continue


if __name__ == "__main__":
    main()