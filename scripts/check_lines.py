import json

with open('demo-app/seeded-vulnerabilities.json') as f:
    v = json.load(f)

for item in v['vulnerabilities']:
    with open(item['file']) as src:
        lines = src.readlines()
    l_idx = item['line'] - 1
    actual = lines[l_idx].strip() if l_idx < len(lines) else 'EOF'
    print(f"{item['id']} at {item['file']}:{item['line']} -> {actual}")
