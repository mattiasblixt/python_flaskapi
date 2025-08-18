'''
Split a dictionary into a specified number
'''
def split_dict(in_dict: dict, num_parts: int) -> list[dict]:
    '''
    Split a dictionary into a specified number of approximately equal parts.

    Args:
        in_dict: The input dictionary to be split.
        num_parts: The number of parts to split the dictionary into.

    Returns:
        A list of dictionaries, each containing approximately equal numbers of key-value pairs.

    Raises:
        TypeError: If in_dict is not a dictionary or num_parts is not an integer.
        ValueError: If num_parts is less than 1.
    '''

    # check types
    if not isinstance(in_dict, dict):
        raise TypeError('''Input 'in_dict' must be a dictionary''')
    if not isinstance(num_parts, int):
        raise TypeError('''Input 'num_parts' must be an integer''')

    # check so we split into alteast 1
    if num_parts < 1:
        raise ValueError('''Number of parts must be at least 1''')

    # Convert dictionary items to a list for slicing
    items = list(in_dict.items())
    no_of_items = len(items)

    # Handle empty dictionary or num_parts larger than number of items
    if no_of_items == 0:
        return [{} for _ in range(num_parts)]

    # Calculate size of each part
    part_size = no_of_items // num_parts + (1 if no_of_items % num_parts else 0)

    # Split items into chunks and convert back to dictionaries
    result = [
        dict(items[i:i + part_size])
        for i in range(0, no_of_items, part_size)
    ]

    # Ensure the result has exactly num_parts by padding with empty dicts if needed
    return result + [{}] * (num_parts - len(result))
