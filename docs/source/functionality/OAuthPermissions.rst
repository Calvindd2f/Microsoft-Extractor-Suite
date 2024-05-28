import os
import csv
import datetime

# Check if the output directory exists, and create it if it doesn't
output_dir = 'output'
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Set the file names and paths
input_file1 = 'data1.txt'
input_file2 = 'data2.txt'
output_file = os.path.join(output_dir, f'output_{datetime.date.today().isoformat()}.csv')

# Read the data from the input files
data1 = []
with open(input_file1, 'r') as f:
    for line in f:
        data1.append(line.strip().split(','))

data2 = []
with open(input_file2, 'r') as f:
    for line in f:
        data2.append(line.strip().split(','))

# Combine the two data sets and sort by client ID
data = sorted(data1 + data2, key=lambda x: int(x[0]))

# Write the data to the output file
with open(output_file, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerows(data)

# Display the output file path
print(f'Output file saved to: {output_file}')
