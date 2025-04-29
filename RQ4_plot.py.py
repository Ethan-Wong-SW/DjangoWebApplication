import pandas as pd
import matplotlib.pyplot as plt
import os

# === Load the last row from each run ===
runs = []
for i in range(1, 9):  # run1.csv to run8.csv
    path = f"zrq4/run{i}.csv"
    if os.path.exists(path):
        df = pd.read_csv(path)
        final = df.iloc[-1]  # get final stats of the run
        runs.append({
            "Session": f"Session {i}",
            "Interesting Tests": final["corpus_size"],
            "Unique Crashes": final["unique_crashes"]
        })
    else:
        print(f"Warning: {path} not found")

# === Create DataFrame ===
df = pd.DataFrame(runs)

# === Plot grouped bar chart ===
x = range(len(df))
width = 0.35

plt.figure(figsize=(10, 6))
plt.bar([p - width/2 for p in x], df["Interesting Tests"], width=width, hatch="//", label="Interesting Tests")
plt.bar([p + width/2 for p in x], df["Unique Crashes"], width=width, hatch="\\\\", label="Unique Crashes")

plt.xticks(x, df["Session"], rotation=45)
plt.ylabel("#interesting tests and unique crashes", color="red")
plt.xlabel("Fuzzing Campaigns (Session #1, Session #2, ..., Session #8)", color="red")
plt.title("RQ4: Stability Across Fuzzing Sessions")
plt.legend()
plt.tight_layout()
plt.savefig("rq4final.png", dpi=300)
print("✅ Plot saved to rq4final.png")

# Optional: show the plot too
plt.show()