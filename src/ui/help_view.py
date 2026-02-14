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
    console.print("  [bold]/refresh[/]           Generate new BB84 key (interactive)")
    console.print("  [bold]/stats[/]             Show statistics")
    console.print("  [bold]/verbose on|off[/]    Toggle encryption details")
    console.print("  [bold]/clear[/]             Clear screen")
    console.print("  [bold]/history[/]           Show message history")
    console.print("  [bold]/export[/]            Export transcript to file")
    console.print("  [bold]/quit[/]              Exit (also Ctrl+C)")
    console.print()
    console.print("[bold]BB84 Interactive Key Exchange:[/]")
    console.print("  [dim]When prompted, enter your bits and bases manually.[/]")
    console.print("  [dim]Bits:  0 or 1, space-separated (e.g. 1 0 1 1 0 0 1 0)[/]")
    console.print("  [dim]Bases: polarization symbols, space-separated:[/]")
    console.print("    [bold]-[/]  horizontal (rectilinear, 0°)")
    console.print("    [bold]|[/]  vertical   (rectilinear, 90°)")
    console.print("    [bold]/[/]  diagonal   (diagonal, 45°)")
    console.print("    [bold]\\[/]  anti-diag  (diagonal, 135°)")
    console.print()
    console.print("[bold]About BB84:[/]")
    console.print("  [dim]BB84 uses quantum mechanics to create shared secret keys.[/]")
    console.print("  [dim]Any eavesdropping disturbs quantum states and is detected.[/]")
    console.print("  [dim]Messages are encrypted via XOR with the quantum key.[/]")
    console.print()
