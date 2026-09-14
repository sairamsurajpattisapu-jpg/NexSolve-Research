import sys, base64
if len(sys.argv) < 3:
    print('Usage: write_file.py <dest> <base64_data>')
    sys.exit(1)
dest = sys.argv[1]
b64 = sys.argv[2]
data = base64.b64decode(b64)
with open(dest, 'wb') as f:
    f.write(data)
print(f'Successfully wrote {len(data)} bytes to {dest}')
