import pandas as pd
from pathlib import Path

# Folder containing all your CSV files
DATA_DIR = Path("/Users/yashvinavadia/Desktop/CSUF/ctrp/data/CWE")

# Get a list of all CSV files in the folder
csv_files = list(DATA_DIR.glob("*.csv"))

# Read and concatenate all CSVs
df_list = [pd.read_csv(file) for file in csv_files]
merged_df = pd.concat(df_list, ignore_index=True)

# Deduplicate entries based on CWE ID (keep the first occurrence)
merged_df = merged_df.drop_duplicates(subset=["CWE ID"], keep="first")

# Optional: reset index
merged_df.reset_index(drop=True, inplace=True)

# Save the merged CSV
merged_df.to_csv(DATA_DIR / "merged_cwe.csv", index=False)

print(f"Merged {len(csv_files)} files into 'merged_cwe.csv' with {len(merged_df)} unique entries.")
