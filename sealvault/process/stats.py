def percentile(ordered, fraction):
    """Linear-interpolation percentile over an already sorted sequence."""
    if not ordered:
        return None
    if len(ordered) == 1:
        return float(ordered[0])
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    share = position - lower
    if lower + 1 >= len(ordered):
        return float(ordered[-1])
    return ordered[lower] + (ordered[lower + 1] - ordered[lower]) * share


def summarize(values):
    """Duration summary in seconds; None when there is no observation."""
    if not values:
        return None
    ordered = sorted(values)
    return {
        'count': len(ordered),
        'min': ordered[0],
        'max': ordered[-1],
        'mean': round(sum(ordered) / len(ordered), 3),
        'median': int(round(percentile(ordered, 0.5))),
        'p90': int(round(percentile(ordered, 0.9))),
    }
