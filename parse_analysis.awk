# Capture the filename
/FILENAME:/ { filename = $2 }

# Capture the metrics
/Optimum compression would reduce the size/ { compression = $8 }
/Entropy =/ { entropy = $3 }
/Serial correlation coefficient is/ { correlation = $5 }

# At the separator, print the table row
/---/ {
    if (entropy != "") {
        # Prints: File | Entropy | Correlation | Compression %
        printf "%-25s | %-8s | %-12s | %-12s\n", filename, entropy, correlation, compression
        # Reset
        entropy = ""; correlation = ""; compression = ""; filename = ""
    }
}