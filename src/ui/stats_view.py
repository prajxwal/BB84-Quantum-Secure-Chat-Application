"""
BB84 Quantum Chat - Statistics View
Compact IRC-style statistics display.
"""

from rich.console import Console
from src.stats.collector import Statistics
from src.crypto.key_manager import KeyManager
from src.ui.colors import SYMBOLS


def display_stats(console: Console, stats: Statistics, key_manager: KeyManager,
                  role: str, peer_address: str = ""):
    """Display statistics in compact IRC format."""
    sec_status = stats.security_status()
    sec_sym = SYMBOLS['secure'] if sec_status == "SECURE" else SYMBOLS['compromised']

    console.print()
    console.print("[bold bright_cyan]═══ Quantum Channel Statistics ═══[/]")
    console.print()

    # Connection
    console.print("[bold]Connection[/]")
    console.print(f"  Status:        {sec_sym} ACTIVE")
    console.print(f"  Role:          {role}")
    if peer_address:
        console.print(f"  Peer:          {peer_address}")
    console.print(f"  Uptime:        {stats.uptime_str()}")
    console.print()

    # Messages
    console.print("[bold]Messages[/]")
    console.print(f"  Sent:          {stats.messages_sent}")
    console.print(f"  Received:      {stats.messages_received}")
    console.print(f"  Total data:    {stats.total_data_str()}")
    console.print()

    # Key
    key = key_manager.get_key()
    console.print("[bold]Current Key[/]")
    if key:
        usage = key.usage_percentage()
        bar_len = 20
        filled = int(bar_len * usage / 100)
        bar = '█' * filled + '░' * (bar_len - filled)
        console.print(f"  ID:            #{key.id}")
        console.print(f"  Length:        {key.length} bits")
        console.print(f"  Usage:         [{bar}] {usage:.0f}%")
        console.print(f"  Remaining:     {key.remaining()} bits")
    else:
        console.print("  [dim]No key established[/]")
    console.print()

    # BB84
    console.print("[bold]BB84 Protocol[/]")
    console.print(f"  Exchanges:     {stats.exchange_count}")
    console.print(f"  Compromised:   {stats.keys_compromised}")
    if stats.exchange_count > 0:
        console.print(f"  Avg match:     {stats.avg_match_rate():.1%}")
        console.print(f"  Avg error:     {stats.avg_error_rate():.1%}")
        console.print(f"  Avg duration:  {stats.avg_duration():.1f}s")
    console.print()

    # Security
    console.print("[bold]Security[/]")
    sec_style = "green" if sec_status == "SECURE" else "red"
    console.print(f"  Status:        [{sec_style}]{sec_sym} {sec_status}[/]")
    console.print(f"  Eve:           {'ACTIVE' if stats.eve_active else 'Off'}")
    console.print(f"  Detections:    {stats.eavesdropper_detected_count}")
    console.print(f"  Auto rotations:{stats.auto_rotations}")
    console.print()
    console.print("[dim]═══════════════════════════════════[/]")
    console.print()
