import pandas as pd
from pathlib import Path

# Path to your manually merged CSV
DATA_FILE = Path("/Users/yashvinavadia/Desktop/CSUF/ctrp/data/CWE/merged.csv")

# Read the CSV
df = pd.read_csv(DATA_FILE, index_col=False)

# Drop duplicates based on 'CWE-ID', keep the first occurrence
df_unique = df.drop_duplicates(subset=["CWE-ID"], keep="first")
print(df_unique.head(5))
print(df_unique.index)

# Save to a new CSV or overwrite the original
OUTPUT_FILE = DATA_FILE.parent / "merged_unique_cwe.csv"
df_unique.to_csv(OUTPUT_FILE, index=False)

print(f"Removed duplicates. Unique entries saved to '{OUTPUT_FILE}' ({len(df_unique)} rows).")
