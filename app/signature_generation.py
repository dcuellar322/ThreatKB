"""Local candidate generation from shared printable sample features."""
import hashlib
import json
import re
import yara


def generate_candidate(samples, name, max_strings=12):
    if not samples or not re.fullmatch(r'[A-Za-z_]\w{0,127}', name, re.ASCII):
        raise ValueError('Provide samples and a valid YARA rule name.')
    features = [{match.decode('ascii') for match in re.findall(rb'[\x20-\x7e]{8,160}', sample)
                 if len(set(match)) >= 5} for sample in samples]
    common = set.intersection(*features)
    common -= {'This program cannot be run in DOS mode.', 'Microsoft Corporation', 'Rich'}
    selected = sorted(common, key=lambda value: (-len(value), value))[:max_strings]
    if not selected:
        raise ValueError('No distinctive shared printable strings found; select related samples.')
    strings = '\n'.join(f'        $s{index} = {json.dumps(value)} ascii' for index, value in enumerate(selected))
    source = f'rule {name} {{\n    strings:\n{strings}\n    condition:\n        all of ($s*)\n}}\n'
    compiled = yara.compile(source=source)
    if not all(compiled.match(data=sample, timeout=5) for sample in samples):
        raise ValueError('Candidate does not match every supplied sample.')
    return {'source': source, 'name': name, 'strings': strings.strip(), 'condition': 'all of ($s*)',
            'sample_sha256': [hashlib.sha256(sample).hexdigest() for sample in samples],
            'feature_count': len(selected),
            'review_note': 'Draft candidate: review context and test against goodware before release.'}
