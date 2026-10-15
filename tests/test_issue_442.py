import io
import yara


def test_generate_candidate_compiles_and_matches_related_samples(authenticated):
    samples = [b'first\x00SYNTHETIC_COMMON_MARKER\x00one', b'second\x00SYNTHETIC_COMMON_MARKER\x00two']
    response = authenticated.post('/ThreatKB/yara_rules/generate', data={
        'name': 'related_samples', 'files': [(io.BytesIO(sample), f'sample-{index}.bin')
                                           for index, sample in enumerate(samples)]})
    assert response.status_code == 200
    compiled = yara.compile(source=response.json['source'])
    assert all(compiled.match(data=sample) for sample in samples)
    assert not compiled.match(data=b'unrelated goodware')
    assert len(response.json['sample_sha256']) == 2
