/**
 * Copyright (c) 2017-2022 Jeremy Salwen and contributors
 *
 * Permission is hereby granted, free of charge, to any
 * person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the
 * Software without restriction, including without
 * limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software
 * is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice
 * shall be included in all copies or substantial portions
 * of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
 * ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
 * SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
 * IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

// Adapted from crate permutation, function permutation::Permutation::apply_slice_bkwd_in_place()
// https://docs.rs/permutation/0.4.1/src/permutation/permutation.rs.html#400

use core::ops::IndexMut;

// For the in place methods, we apply each cycle in the permutation in turn, marking the indices with their MSB when
// they have been resolved. The MSB will always be unset as long as n <= isize::max_value().
// This way, we can recover the original indices in O(n) and perform no heap allocations.
fn toggle_mark_idx(idx: usize) -> usize {
    idx ^ isize::min_value() as usize
}

fn idx_is_marked(idx: usize) -> bool {
    (idx & (isize::min_value() as usize)) != 0
}

pub(crate) fn apply_permutation_backwards<P, T>(permutation: &mut P, data: &mut [T])
where
    P: IndexMut<usize, Output = usize>
{
    assert!(data.len() <= isize::max_value() as usize);

    for i in 0..data.len() {
        debug_assert!(!idx_is_marked(permutation[i]));
    }

    for i in 0..data.len() {
        let i_idx = permutation[i];

        if idx_is_marked(i_idx) {
            continue;
        }

        let mut j = i;
        let mut j_idx = i_idx;

        // When we loop back to the first index, we stop
        while j_idx != i {
            permutation[j] = toggle_mark_idx(j_idx);
            data.swap(j, j_idx);
            j = j_idx;
            j_idx = permutation[j];
        }

        permutation[j] = toggle_mark_idx(j_idx);
    }

    for i in 0..data.len() {
        debug_assert!(idx_is_marked(permutation[i]));
        permutation[i] = toggle_mark_idx(permutation[i]);
    }
}

#[cfg(test)]
mod tests {
    use crate::permutate::apply_permutation_backwards;

    #[test]
    fn apply_permutation_1() {
        let mut data = ['d', 'c', 'a', 'e', 'b'];
        let mut permutation = [2, 4, 1, 0, 3];
        apply_permutation_backwards(&mut permutation, &mut data);
        assert_eq!(data, ['a', 'b', 'c', 'd', 'e']);
        assert_eq!(permutation, [2, 4, 1, 0, 3]);
    }
}
