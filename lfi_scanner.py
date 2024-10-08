import argparse
import os
import subprocess
import logging
import concurrent.futures
import shutil
from pathlib import Path
from rich.console import Console
from rich.progress import Progress


# Setup logging
logging.basicConfig(filename='lfi_scanner.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
console = Console()


# Argument Parser
def get_args():
    parser = argparse.ArgumentParser(description="Intelligent LFI Vulnerability Scanner")
    parser.add_argument("domains_file", help="File containing list of domains")
    parser.add_argument("payloads_file", help="File containing list of LFI payloads")
    parser.add_argument("output_file", help="File to save identified vulnerabilities")
    parser.add_argument("-t", "--threads", type=int, default=12, help="Number of threads for parallel processing")
    return parser.parse_args()


# Run ParamSpider to identify parameters
def run_paramspider(domain):
    # Create the results directory if it doesn't exist
    results_dir = "results"
    os.makedirs(results_dir, exist_ok=True)
    
    # Sanitize domain name for the file path
    sanitized_domain = domain.replace('https://', '').replace('http://', '').replace('/', '_')
    result_file = os.path.join(results_dir, f"{sanitized_domain}.txt")
    
    # Command to run ParamSpider and save results to the specific file
    command = f"paramspider -d {domain} > {result_file}"
    logging.info(f"Running ParamSpider for {domain} and saving results to {result_file}")
    subprocess.run(command, shell=True)
    return result_file


# Filter parameters using gf
def filter_params(result_file):
    # Create the vet directory if it doesn't exist
    vet_dir = "vet"
    os.makedirs(vet_dir, exist_ok=True)
    
    # Define the vetted parameters file within the vet directory
    vet_file = os.path.join(vet_dir, "filtered_params.txt")
    
    command = f"gf lfi {result_file} > {vet_file}"
    logging.info(f"Filtering parameters using gf tool and saving to {vet_file}")
    subprocess.run(command, shell=True)
    return vet_file


# Test for LFI vulnerabilities using Feroxbuster
def run_feroxbuster(domain, param, payload):
    url = f"{domain}?{param}={payload}"
    command = f"feroxbuster -u {url} -o feroxbuster_output.txt -n"
    logging.info(f"Running Feroxbuster for {url}")
    subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return parse_feroxbuster_output("feroxbuster_output.txt")


# Parse Feroxbuster output and check for LFI
def parse_feroxbuster_output(file_path):
    valid_urls = []
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            for line in file:
                if "200" in line:  # Check only for 200 OK responses
                    url = line.split()[0]  # Assuming the URL is the first part of the output
                    if check_lfi(url):
                        valid_urls.append(url)
    return valid_urls


# Simple LFI confirmation based on common patterns
def check_lfi(url):
    try:
        response = subprocess.run(["curl", "-s", url], capture_output=True, text=True)
        if "root:x:0:0:" in response.stdout or "/etc/passwd" in response.stdout:
            logging.info(f"LFI confirmed at {url}")
            return True
    except Exception as e:
        logging.error(f"Error checking LFI at {url}: {e}")
    return False


# Main LFI Scanning Logic
def scan_lfi(domains, payloads, output_file, threads):
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        for domain in domains:
            # Run ParamSpider and filter parameters
            result_file = run_paramspider(domain)
            vet_file = filter_params(result_file)
            
            # Load parameters
            params = [line.strip() for line in open(vet_file)]
            future_to_url = {
                executor.submit(run_feroxbuster, domain, param, payload): (domain, param, payload)
                for param in params for payload in payloads
            }
            valid_lfi_results = []
            with Progress(console=console) as progress:
                task = progress.add_task("[cyan]Testing for LFI...", total=len(future_to_url))
                for future in concurrent.futures.as_completed(future_to_url):
                    valid_lfi = future.result()
                    if valid_lfi:
                        valid_lfi_results.extend(valid_lfi)
                    progress.advance(task)
            with open(output_file, "a") as f:
                for result in valid_lfi_results:
                    f.write(f"{result}\n")
            logging.info(f"Results written to {output_file}")
            
            # Clean up temporary files and directories
            shutil.rmtree("results")
            shutil.rmtree("vet")
            if os.path.exists("feroxbuster_output.txt"):
                os.remove("feroxbuster_output.txt")


# Main Function
def main():
    args = get_args()
    domains = [line.strip() for line in open(args.domains_file)]
    payloads = [line.strip() for line in open(args.payloads_file)]
    scan_lfi(domains, payloads, args.output_file, args.threads)


if __name__ == "__main__":
    main()
