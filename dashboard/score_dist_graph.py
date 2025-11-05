import pandas as pd
import matplotlib.pyplot as plt
from scipy.stats import gaussian_kde

# once run the file and saved the images no need to run further

# Load your merged CWE-CVSS dataset
df = pd.read_csv("/Users/yashvinavadia/Desktop/CSUF/ctrp/data/cves_table.csv")

# Example: Distribution of CVSS v3.1 scores
plt.figure(figsize=(8, 6))
df['cvss_v31'].dropna().hist(bins=20, edgecolor='black')
plt.title("Distribution of CVSS v3.1 Scores")
plt.xlabel("CVSS Score")
plt.ylabel("Frequency")
plt.savefig("cvss_v31_distribution.png", dpi=300)
plt.show()

# Comparison plot: v2 vs v3.1
plt.figure(figsize=(8, 6))
df[['cvss_v2', 'cvss_v31']].plot(kind='kde')
plt.title("CVSS v2 vs v3.1 Score Distribution")
plt.xlabel("CVSS Score")
plt.savefig("cvss_version_comparison.png", dpi=300)
plt.show()
