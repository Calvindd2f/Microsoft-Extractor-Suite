import os
import csv
import datetime

# Function to combine two data sets based on client_id
def combine\_datasets(data\_set1, data\_set2):
client\_map = {item['client\_id']: item for item in data\_set1}
combined\_data = [
{**client\_map[client\_id], **data}
for client\_id, data in {item['client\_id']: item for item in data\_set2}.items()
]
return sorted(combined\_data, key=lambda x: x['client\_id'])

# Function to write data to a CSV file
def write\_to\_csv(data, output\_file):
with open(output\_file, 'w', newline='', encoding='utf-8') as csvfile:
fieldnames = ['client\_id', 'name', 'age', 'city', 'state']
writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
writer.writeheader()
writer.writerows(data)

# Check if the output directory exists, and create it if it doesn't
output\_dir = 'output'
os.makedirs(output\_dir, exist\_ok=True)

# Load the two data sets
data\_set1 = [
{'client\_id': 1, 'name': 'John', 'age': 30},
{'client\_id': 2, 'name': 'Jane', 'age': 25},
{'client\_id': 3, 'name': 'Doe', 'age': 35}
]

data\_set2 = [
{'client\_id': 2, 'city': 'New York', 'state': 'NY'},
{'client\_id': 3, 'city': 'Los Angeles', 'state': 'CA'},
{'client\_id': 1, 'city': 'Chicago', 'state': 'IL'}
]

# Combine the two data sets into a single array
combined\_data = combine\_datasets(data\_set1, data\_set2)

# Add the current date to the output file name
output\_file = f'output/combined\_data_{datetime.date.today().isoformat()}.csv'

# Export the data to CSV with UTF-8 encoding and no type information
write\_to\_csv(combined\_data, output\_file)

# Display the output file path
print(f'Output file saved to: {output\_file}')
