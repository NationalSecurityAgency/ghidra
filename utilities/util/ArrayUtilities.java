/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package utilities.util;

import java.lang.reflect.Array;
import java.util.Arrays;

import ghidra.util.SystemUtilities;

public final class ArrayUtilities {

	/**
	 * Returns a new copy of the specified byte {@code array} with the elements in reversed order.
	 *
	 * @param array byte array to reverse
	 * @return new array instance with elements in reverse order
	 */
	public static byte[] reverse(byte[] array) {

		byte[] reversed = new byte[array.length];

		for (int i = 0; i < reversed.length; i++) {
			reversed[i] = array[array.length - 1 - i];
		}
		return reversed;
	}

	/**
	 * Compares two primitive arrays for equality
	 * 
	 * @param o1 the first array
	 * @param o2 the second array
	 * @return true if each element of the array is equal
	 * @throws IllegalArgumentException if either argument is not an array
	 */
	public static boolean isArrayPrimativeEqual(Object o1, Object o2) {
		if (o1 == null) {
			return (o2 == null);
		}

		if (o2 == null) {
			return false;
		}

		Class<? extends Object> class1 = o1.getClass();
		if (!class1.isArray()) {
			throw new IllegalArgumentException(
				"Object parameters must be an array! Instead found class: " + class1);
		}

		Class<? extends Object> class2 = o2.getClass();
		if (!class2.isArray()) {
			throw new IllegalArgumentException(
				"Object parameters must be an array! Instead found class: " + class2);
		}

		if (Array.getLength(o1) != Array.getLength(o2)) {
			return false;
		}

		for (int i = 0; i < Array.getLength(o1); i++) {
			if (!SystemUtilities.isEqual(Array.get(o1, i), Array.get(o2, i))) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Returns true if a portion of byte array b1 equals an equally sized portion of byte array
	 * b2.
	 * <p>
	 * If the sizes of b1 or b2 do not allow for a full comparison of {@code len} bytes, this
	 * function will return false.
	 * <p>
	 * @param b1 first byte array
	 * @param start_b1 offset to start comparison in b1
	 * @param b2 second byte array
	 * @param start_b2 offset to start comparison in b2
	 * @param len number of bytes to compare
	 * @return true or false if the portion is equal
	 */
	public static boolean arrayRangesEquals(byte[] b1, int start_b1, byte[] b2, int start_b2,
			int len) {
		if (start_b1 + len > b1.length || start_b2 + len > b2.length) {
			return false;
		}
		for (int i = 0; i < len; i++) {
			if (b1[start_b1 + i] != b2[start_b2 + i]) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Returns a copy of the given array with the provided element appended.  The length of
	 * the returned array will be one element greater than the given array.
	 * 
	 * @param array The array to copy.
	 * @param element The element to append to the copy.
	 * @return A copy of the given array with the provided element appended.
	 */
	public static <T> T[] copyAndAppend(T[] array, T element) {
		T[] newArray = Arrays.copyOf(array, array.length + 1);
		newArray[array.length] = element;
		return newArray;
	}

	/**
	 * Compare two byte arrays by their corresponding entries
	 * 
	 * If the two arrays have differing lengths, the shorter precedes the longer. Otherwise, they
	 * are compared as in C's {@code memcmp}, except that Java {@code byte}s are signed.
	 * @param a the first array
	 * @param b the second array
	 * @return a comparison result as in {@link Comparable#compareTo(Object)}
	 */
	public static int compare(byte[] a, byte[] b) {
		int result;
		result = a.length - b.length;
		if (result != 0) {
			return result;
		}
		for (int i = 0; i < a.length; i++) {
			result = a[i] - b[i];
			if (result != 0) {
				return result;
			}
		}
		return 0;
	}
}
