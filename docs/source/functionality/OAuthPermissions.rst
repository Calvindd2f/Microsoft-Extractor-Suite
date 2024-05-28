import os
import csv
import datetime

# Check if the output directory exists, and create it if it doesn't
output_dir = 'output'
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Load the two data sets
data_set1 = [
    {'client_id': 1, 'name': 'John', 'age': 30},
    {'client_id': 2, 'name': 'Jane', 'age': 25},
    {'client_id': 3, 'name': 'Doe', 'age': 35}
]

data_set2 = [
    {'client_id': 2, 'city': 'New York', 'state': 'NY'},
    {'client_id': 3, 'city': 'Los Angeles', 'state': 'CA'},
    {'client_id': 1, 'city': 'Chicago', 'state': 'IL'}
]

# Combine the two data sets into a single array
combined_data = []
for item in data_set1:
    client_id = item['client_id']
    for data in data_set2:
        if data['client_id'] == client_id:
            combined_data.append({**item, **data})

# Sort the data by client ID
combined_data.sort(key=lambda x: x['client_id'])

# Add the current date to the output file name
output_file = f'output/combined_data_{datetime.date.today().isoformat()}.csv'

# Export the data to CSV with UTF-8 encoding and no type information
with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
    fieldnames = ['client_id', 'name', 'age', 'city', 'state']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for data in combined_data:
        writer.writerow(data)

# Display the output file path
print(f'Output file saved to: {output_file}')
