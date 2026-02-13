"""
BB84 Quantum Chat - Eavesdropper Detection View
Compact IRC-style Eve analysis.
"""

from rich.console import Console
from rich.table import Table
from rich import box

from config.constants import BASIS_SYMBOLS
from config.settings import ERROR_THRESHOLD
from src.ui.colors import SYMBOLS


def display_eve_analysis(console: Console, result: dict):
    """Display eavesdropper analysis in compact format."""
    if not result.get('eve_active') or result.get('eve_bits') is None:
        return

    console.print()
    console.print(f"[bold red]{SYMBOLS['warning']} Eve Interception Analysis[/]")

    # Compact interception table
    table = Table(box=box.SIMPLE, show_header=True, header_style="dim", padding=(0, 1))
    table.add_column("Pos", justify="center", width=4)
    table.add_column("Alice", justify="center", width=5)
    table.add_column("Eve", justify="center", width=5)
    table.add_column("Bob", justify="center", width=5)
    table.add_column("", justify="center", width=5)

    alice_bits = result['alice_bits']
    eve_bits = result.get('eve_bits', [])
    bob_bits = result['bob_bits']
    matching_pos = set(result['matching_positions'])

    shown = 0
    for i in range(len(alice_bits)):
        if i not in matching_pos:
            continue
        if shown >= 8:
            break
        a, e, b = alice_bits[i], eve_bits[i], bob_bits[i]
        match = a == b
        sym = f"[green]✓[/]" if match else f"[red]✗[/]"
        table.add_row(str(i + 1), str(a), str(e), str(b), sym)
        shown += 1

    console.print(table)

    # Error summary
    error_rate = result['error_rate']
    sample_pos = result['sample_positions']
    alice_sample = result['alice_sample']
    bob_sample = result['bob_sample']
    errors = sum(a != b for a, b in zip(alice_sample, bob_sample))

    exceeded = error_rate > ERROR_THRESHOLD
    status = f"[bold red]{SYMBOLS['compromised']} EXCEEDED[/]" if exceeded else f"[green]{SYMBOLS['secure']} OK[/]"
    console.print(f"  Errors: {errors}/{len(sample_pos)} │ Rate: {error_rate:.1%} │ Threshold: {ERROR_THRESHOLD:.0%} │ {status}")
    console.print()
