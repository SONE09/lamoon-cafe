"""Create a consistent SQLite backup while the cafe is running."""
import argparse
import sqlite3
from datetime import datetime
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
root = Path(__file__).resolve().parent
parser.add_argument('--db', type=Path, default=root / 'data' / 'cafe.db')
args = parser.parse_args()
if not args.db.is_file():
    parser.error('Database does not exist. Start the cafe first.')
folder = root / 'backups'
folder.mkdir(exist_ok=True)
target = folder / ('cafe-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f') + '.db')
with sqlite3.connect(args.db.resolve().as_uri() + '?mode=ro', uri=True) as source:
    with sqlite3.connect(target) as destination:
        source.backup(destination)
print(target)
