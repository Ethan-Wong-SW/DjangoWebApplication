import pandas as pd
import matplotlib.pyplot as plt
import os

# === Load and flatten corpus ===
def load_corpus(filepath, label):
    df = pd.read_csv(filepath)
    df = df[df["executed"] <= 400] 
    df["label"] = label
    return df

# === Load all files ===
base = "finalzrq3"
files = {
    "All": os.path.join(base, "remove_nth.csv"),
    "Remove assign_energy": os.path.join(base, "remove_energy.csv"),
    "Remove smart_mutate": os.path.join(base, "remove_smart_mut.csv"),
    "Remove is_interesting": os.path.join(base, "remove_int.csv")
}

dfs = [load_corpus(path, label) for label, path in files.items()]
df_all = pd.concat(dfs)

# === Plot step graph ===
plt.figure(figsize=(10, 6))
for label, group in df_all.groupby("label"):
    plt.step(group["executed"], group["interesting_tests"], where="post", label=label)

plt.xlabel("Number of Tests Executed")
plt.ylabel("Corpus Size (Interesting Tests)")
plt.title("RQ3 Ablation Study: Corpus Growth Over Time")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig("RQ3_ablation_graph.png", dpi=300)
plt.show()
