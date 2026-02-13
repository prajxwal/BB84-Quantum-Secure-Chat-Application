"""
BB84 Quantum Chat - Help Screen
Compact IRC-style help display.
"""

from rich.console import Console


def display_help(console: Console):
    """Display help in IRC format."""
    console.print()
    console.print("[bold bright_cyan]═══ BB84 Quantum Chat Help ═══[/]")
    console.print()
    console.print("[bold]Commands:[/]")
    console.print("  [bold]/help[/]              Show this help")
    console.print("  [bold]/key[/]               Show current encryption key")
    console.print("  [bold]/refresh[/]           Generate new BB84 key")
    console.print("  [bold]/stats[/]             Show statistics")
    console.print("  [bold]/eve on|off[/]        Toggle eavesdropper simulation")
    console.print("  [bold]/verbose on|off[/]    Toggle encryption details")
    console.print("  [bold]/clear[/]             Clear screen")
    console.print("  [bold]/history[/]           Show message history")
    console.print("  [bold]/export[/]            Export transcript to file")
    console.print("  [bold]/quit[/]              Exit (also Ctrl+C)")
    console.print()
    console.print("[bold]About BB84:[/]")
    console.print("  [dim]BB84 uses quantum mechanics to create shared secret keys.[/]")
    console.print("  [dim]Any eavesdropping disturbs quantum states and is detected.[/]")
    console.print("  [dim]Messages are encrypted via XOR with the quantum key.[/]")
    console.print()
