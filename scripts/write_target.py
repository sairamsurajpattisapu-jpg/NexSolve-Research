import sys, base64
target = sys.argv[1]
b64_file = sys.argv[2]
with open(b64_file, 'r', encoding='utf-8') as f:
    data = base64.b64decode(f.read().strip())
with open(target, 'wb') as f:
    f.write(data)
print('Written', target)