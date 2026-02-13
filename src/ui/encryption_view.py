"""
BB84 Quantum Chat - Encryption Visualization
Compact IRC-style encryption display.
"""

from rich.console import Console
from src.crypto.utils import bits_to_string


def display_encryption(console: Console, details: dict, direction: str = "SENDING"):
    """Display compact encryption info in IRC style."""
    msg = details['message']
    msg_bits = details['message_bits']
    key_bits = details['key_bits']
    cipher_bits = details['cipher_bits']
    ciphertext = details['ciphertext_hex']
    bits_used = details['bits_used']

    console.print(f"[dim]  ┌─ Encrypt: \"{msg}\"[/]")
    console.print(f"[dim]  │ Msg: {bits_to_string(msg_bits[:24])} ...[/]")
    console.print(f"[dim]  │ Key: {bits_to_string(key_bits[:24])} ...[/]")
    console.print(f"[dim]  │ XOR: {bits_to_string(cipher_bits[:24])} ...[/]")
    console.print(f"[dim]  └─ Cipher:[/] [bold magenta]{ciphertext}[/] [dim]({bits_used}b used)[/]")


def display_decryption(console: Console, details: dict):
    """Display compact decryption info."""
    ciphertext = details['ciphertext_hex']
    plaintext = details['plaintext']
    bits_used = details['bits_used']

    console.print(f"[dim]  ┌─ Decrypt: {ciphertext}[/]")
    console.print(f"[dim]  └─ Plain:[/] [bold green]{plaintext}[/] [dim]({bits_used}b)[/]")
