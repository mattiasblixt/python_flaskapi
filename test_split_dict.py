'''
test class file for the split_dict function.
'''
import unittest
from split_dict import split_dict

class TestSplitDictEvenly(unittest.TestCase):
    '''
    Test cases for the split_dict function.
    '''

    def test_normal_split(self):
        '''
        Test splitting a dictionary into equal parts.
        '''
        d = {'a': 1, 'b': 2, 'c': 3, 'd': 4, 'e': 5}
        result = split_dict(d, 2)
        expected = [{'a': 1, 'b': 2, 'c': 3}, {'d': 4, 'e': 5}]
        self.assertEqual(result, expected)

    def test_uneven_split(self):
        '''
        Test splitting with uneven parts.
        '''
        d = {'a': 1, 'b': 2, 'c': 3}
        result = split_dict(d, 2)
        expected = [{'a': 1, 'b': 2}, {'c': 3}]
        self.assertEqual(result, expected)

    def test_empty_dict(self):
        '''
        Test splitting an empty dictionary.
        '''
        d = {}
        result = split_dict(d, 3)
        expected = [{}, {}, {}]
        self.assertEqual(result, expected)

    def test_single_part(self):
        '''
        Test splitting into a single part.
        '''
        d = {'a': 1, 'b': 2}
        result = split_dict(d, 1)
        expected = [{'a': 1, 'b': 2}]
        self.assertEqual(result, expected)

    def test_more_parts_than_items(self):
        '''
        Test when num_parts exceeds number of items.
        '''
        d = {'a': 1, 'b': 2}
        result = split_dict(d, 4)
        expected = [{'a': 1}, {'b': 2}, {}, {}]
        self.assertEqual(result, expected)

    def test_type_error_dict(self):
        '''
        Test raising TypeError for non-dictionary input.
        '''
        with self.assertRaises(TypeError):
            split_dict([1, 2, 3], 2)

    def test_type_error_num_parts(self):
        '''
        Test raising TypeError for non-integer num_parts.
        '''
        with self.assertRaises(TypeError):
            split_dict({'a': 1}, 2.5)

    def test_value_error_num_parts(self):
        '''
        Test raising ValueError for num_parts < 1.
        '''
        with self.assertRaises(ValueError):
            split_dict({'a': 1}, 0)
        with self.assertRaises(ValueError):
            split_dict({'a': 1}, -1)

    def test_large_dictionary(self):
        '''
        Test splitting a large dictionary.
        '''
        d = {str(i): i for i in range(100)}
        result = split_dict(d, 10)
        self.assertEqual(len(result), 10)
        self.assertEqual(sum(len(part) for part in result), 100)
        for part in result[:9]:
            self.assertEqual(len(part), 10)
        self.assertEqual(len(result[9]), 10)

    def test_order_preservation(self):
        '''
        Test that dictionary order is preserved.
        '''
        d = {'a': 1, 'b': 2, 'c': 3}
        result = split_dict(d, 2)
        self.assertEqual(list(result[0].keys()), ['a', 'b'])
        self.assertEqual(list(result[1].keys()), ['c'])


if __name__ == '__main__':
    unittest.main()
