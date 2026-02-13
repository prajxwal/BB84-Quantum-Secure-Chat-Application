"""
BB84 Quantum Chat - Main UI Controller
IRC-style interface: clean message flow, compact system messages, minimal panels.
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box

from src.ui.colors import CHAT_THEME, SYMBOLS
from src.crypto.key_manager import KeyManager
from src.crypto.utils import key_to_hex
from src.stats.collector import Statistics
from src.chat.history import ChatHistory
from src.chat.message import Message


def create_console() -> Console:
    """Create a Rich console with our theme."""
    return Console(theme=CHAT_THEME, highlight=False)


def display_header(console: Console, role: str, peer: str, key_manager: KeyManager,
                   stats: Statistics):
    """Display a compact IRC-style header bar."""
    key = key_manager.get_key()
    key_len = key.length if key else 0
    key_usage = f"{key.usage_percentage():.0f}%" if key else "N/A"
    msg_count = stats.total_messages()
    error_rate = stats.last_error_rate
    sec_status = stats.security_status()
    sec_sym = SYMBOLS['secure'] if sec_status == "SECURE" else SYMBOLS['compromised']

    console.print(f"[bold bright_cyan]─── BB84 Quantum Chat ───[/] "
                  f"[dim]Key:{key_len}b ({key_usage}) │ Msgs:{msg_count} │ "
                  f"Err:{error_rate:.1%} │ {sec_sym} {sec_status}[/]")
    console.print()


def display_message(console: Console, msg: Message, show_encrypted: bool = True):
    """Display a message in IRC format: <Sender> message"""
    time_str = msg.time_str()
    sender = msg.sender
    style = "bold cyan" if sender.lower() == "alice" else "bold green"

    console.print(f"[dim]{time_str}[/] [{style}]<{sender}>[/] {msg.content}")
    if show_encrypted and msg.encrypted:
        console.print(f"         [dim]│ {SYMBOLS['lock']} {msg.encrypted}[/]")


def display_system_message(console: Console, text: str, level: str = "INFO"):
    """Display a system message with IRC-style prefix."""
    from datetime import datetime
    time_str = datetime.now().strftime('%H:%M:%S')

    prefixes = {
        'INFO':    ('[dim]', '---'),
        'WARNING': ('[bold yellow]', '⚠ '),
        'ERROR':   ('[bold red]', '!!!'),
        'SUCCESS': ('[bold green]', '>>>'),
    }
    style, prefix = prefixes.get(level, ('[dim]', '---'))
    console.print(f"[dim]{time_str}[/] {style}{prefix} {text}[/]")


def display_status_bar(console: Console, key_manager: KeyManager, stats: Statistics):
    """Display a compact one-line status bar."""
    key = key_manager.get_key()
    if key:
        usage_pct = key.usage_percentage()
        bar_len = 20
        filled = int(bar_len * usage_pct / 100)
        bar = '█' * filled + '░' * (bar_len - filled)
        rotation_age = int(key.age_seconds())
        age_str = f"{rotation_age // 60}m" if rotation_age >= 60 else f"{rotation_age}s"

        console.print(f"[dim]─── Key:[/] [{bar}] [dim]{usage_pct:.0f}% "
                      f"({key.bits_used}/{key.length}b) │ Age: {age_str} ───[/]")
    else:
        console.print("[dim]─── No key. Type /refresh to generate. ───[/]")
    console.print()


def display_key_info(console: Console, key_manager: KeyManager):
    """Display current key details (/key command)."""
    key = key_manager.get_key()
    if not key:
        display_system_message(console, "No key established. Use /refresh.", "WARNING")
        return

    key_hex = key_to_hex(key.bits[:64])
    key_binary = ' '.join(str(b) for b in key.bits[:32])
    if len(key.bits) > 32:
        key_binary += ' ...'

    console.print(f"[dim]───────── Encryption Key ─────────[/]")
    console.print(f"  [bold magenta]ID:[/]        #{key.id}")
    console.print(f"  [bold magenta]Length:[/]    {key.length} bits")
    console.print(f"  [bold magenta]Age:[/]       {int(key.age_seconds())}s")
    console.print(f"  [bold magenta]Error:[/]     {key.error_rate:.1%}")
    console.print(f"  [bold magenta]Hex:[/]       {key_hex}")
    console.print(f"  [bold magenta]Used:[/]      {key.bits_used}/{key.length} ({key.usage_percentage():.0f}%)")
    console.print(f"  [bold magenta]Remaining:[/] {key.remaining()} bits")
    console.print(f"[dim]──────────────────────────────────[/]")


def display_chat_history(console: Console, history: ChatHistory, show_encrypted: bool = True):
    """Display all messages in history."""
    messages = history.get_all()
    if not messages:
        display_system_message(console, "No messages yet.", "INFO")
        return

    console.print(f"[dim]─── Message History ({len(messages)} messages) ───[/]")
    for msg in messages:
        display_message(console, msg, show_encrypted)
    console.print(f"[dim]─── End of History ───[/]")


def display_welcome(console: Console, role: str):
    """Display a compact IRC-style welcome banner."""
    console.print()
    console.print("[bold bright_cyan]╔══════════════════════════════════════════════╗[/]")
    console.print("[bold bright_cyan]║[/]  [bold bright_white]BB84 QUANTUM SECURE CHAT[/]                   [bold bright_cyan]║[/]")
    console.print("[bold bright_cyan]║[/]  [dim]Quantum Key Distribution • XOR Encryption[/] [bold bright_cyan]║[/]")
    console.print("[bold bright_cyan]╚══════════════════════════════════════════════╝[/]")
    console.print()
    console.print(f"  [dim]Role:[/] [bold]{role}[/]  [dim]│  Type[/] [bold]/help[/] [dim]for commands[/]")
    console.print()
