from app.models.releases import summarize_release_ranges


def test_release_ranges_compress_long_runs_but_preserve_gaps():
    metadata = {index: {"name": f"Release {index}"} for index in range(1, 101)}
    ranges = summarize_release_ranges([*range(1, 61), *range(70, 101)], metadata)
    assert len(ranges) == 2
    assert (ranges[0]["first_id"], ranges[0]["last_id"], ranges[0]["count"]) == (
        1,
        60,
        60,
    )
    assert (ranges[1]["first_id"], ranges[1]["last_id"], ranges[1]["count"]) == (
        70,
        100,
        31,
    )
