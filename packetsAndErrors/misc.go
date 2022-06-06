package packetsAndErrors

// Public constants for the network layers.
//
// The link layer is 2. the network layer is 3.
const (
	LinkLayer int8 = iota + 2
	NetworkLayer
)

// Public constants for the flow directions.
//
// FlowLeftToRight is 0. FlowRightToLeft is 1.
const (
	FlowLeftToRight int8 = iota
	FlowRightToLeft
)

// reverseSlice is a private function to reverse a slice of a type T.
// Slice [5, 3, 4, 8, 42] will be reversed to [42, 8, 4, 3, 5].
//
// Takes:
//	s	[]T	- the slice of type T to reverse
func reverseSlice[T any](s []T) {
	for left, right := 0, len(s)-1; left < right; left, right = left+1, right-1 {
		s[left], s[right] = s[right], s[left]
	}
}

// stringSliceContains is a private function which checks if a slice of strings contains a given string.
//
// Takes:
//	strings	[]string	- a slice of strings which could contain the given string
//	s		string		- a sting that could be contained in the slice of strings
//
// Returns:
//	bool	- true if the slice contains the string, false if not
func stringSliceContains(strings []string, s string) bool {
	for _, s2 := range strings {
		if s == s2 {
			return true
		}
	}

	return false
}

// removeObjectFromSliceAtIndex is a private function to remove an object at a given index from a slice of type T.
// Removes the object as a side effect.
//
// Takes:
//	index	int		- the index at which the object should be removed
//	slice	*[]T	- a pointer to a slice of type T from which the object at the given index should be removed.
func removeObjectFromSliceAtIndex[T any](index int, slice *[]T) {
	*slice = append((*slice)[:index], (*slice)[index+1:]...)
}
