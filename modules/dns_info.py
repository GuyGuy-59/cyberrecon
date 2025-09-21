import re
import dnslib
import dns.resolver
import dns.zone
import socket
import ssl
import dns.query
import dns.message
import dns.rdata
import json
import os
import time
from .config import *

def req_dns_types(victim, logger):
    """Enhanced DNS record enumeration with better error handling and structured output"""
    logger.info(f"Starting DNS record enumeration for: {victim}")
    
    types = ['A', 'AAAA', 'CAA', 'CNAME', 'MX', 'NS', 'TXT', 'DNSKEY', 'DS', 'SOA']
    dns_results = {
        'target': victim,
        'scan_date': time.strftime('%Y-%m-%d %H:%M'),
        'records': {},
        'total_records': 0
    }
    
    for record_type in types:
        try:
            logger.info(f"Querying {record_type} records...")
            q = dnslib.DNSRecord.question(victim, record_type)
            pkt = q.send(dns_resolver, 53, tcp='UDP')
            ans = str(dnslib.DNSRecord.parse(pkt)).split("\n")
            
            # Filter out comments and empty lines
            records = [entry.strip() for entry in ans if entry.strip() and not entry.startswith(';')]
            
            if records:
                dns_results['records'][record_type] = records
                logger.info(f"✓ Found {len(records)} {record_type} records")
                
                # Log first few records as examples
                for i, record in enumerate(records[:3]):
                    logger.info(f"  {record}")
                if len(records) > 3:
                    logger.info(f"  ... and {len(records) - 3} more")
            else:
                logger.info(f"No {record_type} records found")
                dns_results['records'][record_type] = []
                
        except Exception as e:
            logger.error(f"Error querying {record_type} records for {victim}: {e}")
            dns_results['records'][record_type] = []
    
    # Calculate total records
    dns_results['total_records'] = sum(len(records) for records in dns_results['records'].values())
    
    # Save results to file
    try:
        results_dir = os.path.join(result, victim)
        os.makedirs(results_dir, exist_ok=True)
        
        filename = os.path.join(results_dir, "dns_records.json")
        with open(filename, 'w') as f:
            json.dump(dns_results, f, indent=4, ensure_ascii=False)
        
        logger.info(f"DNS records saved to: {filename}")
    except Exception as e:
        logger.error(f"Failed to save DNS records: {e}")
    
    # Display summary
    logger.info(f"\n--- DNS Records Summary for {victim} ---")
    logger.info(f"Total records found: {dns_results['total_records']}")
    
    for record_type, records in dns_results['records'].items():
        if records:
            logger.info(f"{record_type}: {len(records)} records")
    
    return dns_results

def check_dns_caa(victim, logger):
    """Enhanced CAA record checking with better error handling and structured output"""
    logger.info(f"Checking CAA records for: {victim}")
    
    caa_results = {
        'target': victim,
        'scan_date': time.strftime('%Y-%m-%d %H:%M'),
        'caa_records': [],
        'caa_found': False
    }
    
    try:
        answers = dns.resolver.resolve(victim, 'CAA')
        for answer in answers:
            try:
                flags, tag, value = answer.to_text().split(" ", 2)
                caa_record = {
                    'flags': flags,
                    'tag': tag,
                    'value': value
                }
                caa_results['caa_records'].append(caa_record)
                caa_results['caa_found'] = True
                logger.info(f"✓ CAA record found: flags='{flags}', tag='{tag}', value='{value}'")
            except ValueError as e:
                logger.warning(f"Error parsing CAA record: {e}")
                continue
                
    except dns.resolver.NXDOMAIN:
        logger.error(f"Domain {victim} does not exist")
        caa_results['error'] = "Domain does not exist"
    except dns.resolver.NoAnswer:
        logger.info(f"No CAA record found for {victim}")
        caa_results['error'] = "No CAA record found"
    except dns.resolver.NoNameservers:
        logger.error(f"No nameservers found for {victim}")
        caa_results['error'] = "No nameservers found"
    except Exception as e:
        logger.error(f"Error checking CAA records: {e}")
        caa_results['error'] = str(e)
    
    # Save results
    try:
        results_dir = os.path.join(result, victim)
        os.makedirs(results_dir, exist_ok=True)
        
        filename = os.path.join(results_dir, "caa_records.json")
        with open(filename, 'w') as f:
            json.dump(caa_results, f, indent=4, ensure_ascii=False)
        
        logger.info(f"CAA records saved to: {filename}")
    except Exception as e:
        logger.error(f"Failed to save CAA records: {e}")
    
    return caa_results


def check_dns_mx(victim, logger):
    """Enhanced email security records checking (SPF, DKIM, DMARC) with structured output"""
    logger.info(f"Checking email security records for: {victim}")
    
    email_security_results = {
        'target': victim,
        'scan_date': time.strftime('%Y-%m-%d %H:%M'),
        'spf': {'found': False, 'policies': [], 'analysis': []},
        'dkim': {'found': False, 'selectors': [], 'records': []},
        'dmarc': {'found': False, 'policy': None, 'records': []}
    }
    
    # Check SPF
    logger.info("Checking SPF records...")
    try:
        q = dnslib.DNSRecord.question(victim, 'TXT')
        pkt = q.send(dns_resolver, 53, tcp='UDP')
        spf_ans = str(dnslib.DNSRecord.parse(pkt)).split('\n')

        spf_policies = []
        for entry in spf_ans:
            if "v=spf1" in entry:
                matches = re.search(r"v=spf1\s+(.+)", entry)
                if matches:
                    policy = matches.group(1)
                    spf_policies.append(policy)
                    email_security_results['spf']['policies'].append(policy)
                    email_security_results['spf']['found'] = True

        policy_responses = {
            "+all": "SPF policy permits all email",
            "-all": "SPF policy blocks all email", 
            "~all": "SPF policy soft fails all email",
            "?all": "SPF policy has no policy"
        }
        
        for policy in spf_policies:
            analysis = []
            for key, response in policy_responses.items():
                if key in policy:
                    analysis.append(response)
                    break
            else:
                analysis.append("No known SPF directive found in policy")
            
            email_security_results['spf']['analysis'].extend(analysis)
            logger.info(f"✓ SPF policy found: {policy}")
            for msg in analysis:
                logger.info(f"  {msg}")
        
        if not spf_policies:
            logger.info("No SPF records found")
            
    except Exception as e:
        logger.error(f"Error checking SPF records: {e}")

    # Check DKIM
    logger.info("Checking DKIM records...")
    selects = ['default', 's', 's1', 's2', 's1024', 'google', 'mandrill', 'mail']
    dkim_selectors = []
    
    for select in selects:
        try:
            q = dnslib.DNSRecord.question(f"{select}._domainkey.{victim}", "CNAME")
            pkt = q.send(dns_resolver, 53, tcp='UDP')
            cname_ans = str(dnslib.DNSRecord.parse(pkt)).split("\n")
            
            for entry in cname_ans:
                if entry.startswith(f'{select}._domainkey'):
                    selector_match = re.search(r"^.*?CNAME\s+(\S+)\._domainkey\..+$", entry)
                    if selector_match:
                        selector = selector_match.group(1)
                        dkim_selectors.append(selector)
                        email_security_results['dkim']['selectors'].append(selector)
                        email_security_results['dkim']['found'] = True
                        
                        # Get DKIM TXT record
                        try:
                            q = dnslib.DNSRecord.question(f"{selector}._domainkey.{victim}", "TXT")
                            pkt = q.send(dns_resolver, 53, tcp='UDP')
                            dkim_ans = str(dnslib.DNSRecord.parse(pkt)).split("\n")
                            
                            for dkim_entry in dkim_ans:
                                if dkim_entry.startswith(selector):
                                    email_security_results['dkim']['records'].append(dkim_entry)
                                    logger.info(f"✓ DKIM record found for selector {selector}")
                                    break
                        except Exception as e:
                            logger.warning(f"Error getting DKIM TXT record for selector {selector}: {e}")
        except Exception as e:
            logger.warning(f"Error checking DKIM selector {select}: {e}")
    
    if not dkim_selectors:
        logger.info("No DKIM records found")

    # Check DMARC
    logger.info("Checking DMARC records...")
    try:
        q = dnslib.DNSRecord.question(f"_dmarc.{victim}", "TXT")
        pkt = q.send(dns_resolver, 53, tcp='UDP')
        dmarc_ans = str(dnslib.DNSRecord.parse(pkt)).split("\n")
        
        dmarc_records = []
        for entry in dmarc_ans:
            if entry.startswith('_dmarc'):
                dmarc_records.append(entry)
                email_security_results['dmarc']['records'].append(entry)
                email_security_results['dmarc']['found'] = True
                
                policy_match = re.search(r'p=(none|quarantine|reject)', entry)
                if policy_match:
                    policy = policy_match.group(1)
                    email_security_results['dmarc']['policy'] = policy
                    
                    policy_messages = {
                        "none": "DMARC policy is set to none - potentially vulnerable",
                        "quarantine": "DMARC policy is set to quarantine - may be vulnerable", 
                        "reject": "DMARC policy is set to reject - not vulnerable"
                    }
                    
                    logger.info(f"✓ DMARC policy found: {policy}")
                    logger.info(f"  {policy_messages.get(policy, 'Unknown policy')}")
                else:
                    logger.info("DMARC record found but no policy detected")
        
        if not dmarc_records:
            logger.info("No DMARC records found")
            
    except Exception as e:
        logger.error(f"Error checking DMARC records: {e}")
    
    # Save results
    try:
        results_dir = os.path.join(result, victim)
        os.makedirs(results_dir, exist_ok=True)
        
        filename = os.path.join(results_dir, "email_security_records.json")
        with open(filename, 'w') as f:
            json.dump(email_security_results, f, indent=4, ensure_ascii=False)
        
        logger.info(f"Email security records saved to: {filename}")
    except Exception as e:
        logger.error(f"Failed to save email security records: {e}")
    
    # Display summary
    logger.info(f"\n--- Email Security Summary for {victim} ---")
    logger.info(f"SPF: {'✓ Found' if email_security_results['spf']['found'] else '✗ Not found'}")
    logger.info(f"DKIM: {'✓ Found' if email_security_results['dkim']['found'] else '✗ Not found'}")
    logger.info(f"DMARC: {'✓ Found' if email_security_results['dmarc']['found'] else '✗ Not found'}")
    
    return email_security_results


def dns_zone_xfer(victim, logger):
    """Enhanced DNS zone transfer testing with structured output"""
    logger.info(f"Testing DNS zone transfer for: {victim}")
    
    zone_transfer_results = {
        'target': victim,
        'scan_date': time.strftime('%Y-%m-%d %H:%M'),
        'nameservers': [],
        'zone_transfer_attempts': [],
        'vulnerable_servers': []
    }
    
    my_resolver = dns.resolver.Resolver()
    my_resolver.nameservers = [dns_resolver]
    
    try:
        ns_answer = my_resolver.query(victim, 'NS')
        logger.info(f"Found {len(ns_answer)} nameservers")
        
        for server in ns_answer:
            server_info = {
                'nameserver': str(server),
                'ip_addresses': [],
                'zone_transfer_status': 'unknown'
            }
            
            logger.info(f"Testing nameserver: {server}")
            
            try:
                ip_answer = my_resolver.query(server.target, 'A')
                for ip in ip_answer:
                    ip_str = str(ip)
                    server_info['ip_addresses'].append(ip_str)
                    logger.info(f"  IP: {ip_str}")
                    
                    # Test zone transfer
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(ip_str, victim))
                        transfer_status = "vulnerable"
                        server_info['zone_transfer_status'] = 'vulnerable'
                        zone_transfer_results['vulnerable_servers'].append({
                            'nameserver': str(server),
                            'ip': ip_str,
                            'status': 'vulnerable'
                        })
                        logger.warning(f"  ⚠️  Zone transfer VULNERABLE on {server} ({ip_str})")
                    except Exception as e:
                        transfer_status = "protected"
                        server_info['zone_transfer_status'] = 'protected'
                        logger.info(f"  ✓ Zone transfer protected on {server} ({ip_str})")
                    
                    zone_transfer_results['zone_transfer_attempts'].append({
                        'nameserver': str(server),
                        'ip': ip_str,
                        'status': transfer_status
                    })
                    
            except dns.resolver.LifetimeTimeout:
                logger.warning(f"Timeout resolving IP for {server}")
                server_info['zone_transfer_status'] = 'timeout'
            except Exception as e:
                logger.error(f"Error resolving IP for {server}: {e}")
                server_info['zone_transfer_status'] = 'error'
            
            zone_transfer_results['nameservers'].append(server_info)
            
    except dns.resolver.LifetimeTimeout:
        logger.error(f"Timeout resolving NS records for {victim}")
        zone_transfer_results['error'] = "Timeout resolving NS records"
    except Exception as e:
        logger.error(f"Error during zone transfer test: {e}")
        zone_transfer_results['error'] = str(e)
    
    # Save results
    try:
        results_dir = os.path.join(result, victim)
        os.makedirs(results_dir, exist_ok=True)
        
        filename = os.path.join(results_dir, "zone_transfer_test.json")
        with open(filename, 'w') as f:
            json.dump(zone_transfer_results, f, indent=4, ensure_ascii=False)
        
        logger.info(f"Zone transfer test results saved to: {filename}")
    except Exception as e:
        logger.error(f"Failed to save zone transfer results: {e}")
    
    # Display summary
    logger.info(f"\n--- Zone Transfer Test Summary for {victim} ---")
    vulnerable_count = len(zone_transfer_results['vulnerable_servers'])
    if vulnerable_count > 0:
        logger.warning(f"⚠️  {vulnerable_count} nameservers are vulnerable to zone transfer")
    else:
        logger.info("✓ No vulnerable nameservers found")
    
    return zone_transfer_results

def verify_tls_connection(server, port, logger):
    """Enhanced TLS connection verification with better error handling"""
    try:
        sock = socket.create_connection((server, port), timeout=10)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with context.wrap_socket(sock, server_hostname=server) as ssock:
            logger.info(f"✓ TLS connection successful with {server}:{port}")
            return True
    except socket.timeout:
        logger.error(f"TLS connection timeout with {server}:{port}")
        return False
    except ConnectionRefusedError:
        logger.error(f"TLS connection refused by {server}:{port}")
        return False
    except Exception as e:
        logger.error(f"TLS connection error with {server}:{port}: {e}")
        return False

def check_query_dot(server, domain, logger, port=853):
    """Enhanced DNS over TLS query with structured output"""
    logger.info(f"Testing DNS over TLS with {server}:{port} for {domain}")
    
    dot_results = {
        'server': server,
        'port': port,
        'domain': domain,
        'scan_date': time.strftime('%Y-%m-%d %H:%M'),
        'connection_successful': False,
        'query_successful': False,
        'records': []
    }
    
    if not verify_tls_connection(server, port, logger):
        logger.error(f"Unable to contact DoT server at {server}:{port}")
        return dot_results
    
    dot_results['connection_successful'] = True

    try:
        query = dns.message.make_query(domain, dns.rdatatype.A)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        response = dns.query.tls(query, server, port=port, timeout=10, ssl_context=context)
        dot_results['query_successful'] = True

        logger.info(f"✓ DNS over TLS query successful")
        logger.info(f"Response from {server}:{port} for {domain} (type A):")
        
        for answer in response.answer:
            record_str = str(answer)
            dot_results['records'].append(record_str)
            logger.info(f"  {record_str}")

    except Exception as e:
        logger.error(f"DNS over TLS query error: {e}")
        dot_results['error'] = str(e)
    
    # Save results
    try:
        results_dir = os.path.join(result, domain)
        os.makedirs(results_dir, exist_ok=True)
        
        filename = os.path.join(results_dir, f"dot_test_{server.replace('.', '_')}.json")
        with open(filename, 'w') as f:
            json.dump(dot_results, f, indent=4, ensure_ascii=False)
        
        logger.info(f"DNS over TLS test results saved to: {filename}")
    except Exception as e:
        logger.error(f"Failed to save DNS over TLS results: {e}")
    
    return dot_results
