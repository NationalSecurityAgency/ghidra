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

import static org.junit.Assert.*;
import org.junit.Test;


class ArrayUtilitiesTest {

    /**
     * Testing the reverse() function. Two arrays are created, one being the original array, and
     * other being the reverse of that. Then with a for-loop test checks if each and every entry of
     * the returned input is the same as the expected array. Length is also checked.
     */
    @Test
    void reverseTest() {
        byte[] normalArray = {0, 1, 2, 3, 4, 5, 6};
        byte[] expectedReversedArray = {6, 5, 4, 3, 2, 1, 0};

        byte[] returnedArray = ArrayUtilities.reverse(normalArray);

        assertEquals(expectedReversedArray.length, returnedArray.length);

        for(int i = 0; i < returnedArray.length; i++){
            assertEquals(expectedReversedArray[i], returnedArray[i]);
        }

    }

    /**
     * Testing first branch of isArrayPrimitiveEqual().
     */
    @Test
    void isArrayPrimitiveEqual_o1Ando2NullTest() {
        assertTrue(ArrayUtilities.isArrayPrimativeEqual(null, null));
    }

    /**
     * Testing second branch of isArrayPrimitiveEqual().
     */
    @Test
    void isArrayPrimitiveEqual_o2IsNullTest() {
        assertFalse(ArrayUtilities.isArrayPrimativeEqual(new int[]{}, null));
    }

    /**
     * Testing third branch of isArrayPrimitiveEqual().
     */
    @Test(expected = IllegalArgumentException.class)
    void isArrayPrimitiveEqual_o1NotArrayTest() {
        ArrayUtilities.isArrayPrimativeEqual(5, new int[]{});
    }

    /**
     * Testing fourth branch of isArrayPrimitiveEqual().
     */
    @Test(expected = IllegalArgumentException.class)
    void isArrayPrimitiveEqual_o2NotArrayTest() {
        ArrayUtilities.isArrayPrimativeEqual(new int[]{}, 5);
    }

    /**
     * Testing fifth branch of isArrayPrimitiveEqual().
     */
    @Test
    void isArrayPrimitiveEqual_unequalLengthsTest() {
        assertFalse(ArrayUtilities.isArrayPrimativeEqual(new int[]{1}, new int[]{1, 2}));
    }

    /**
     * Testing isArrayPrimitiveEqual with the different arrays of the same length.
     */
    @Test
    void isArrayPrimitiveEqual_differentArraysTest() {
        assertFalse(ArrayUtilities.isArrayPrimativeEqual(new int[]{2, 1}, new int[]{1, 2}));
    }

    /**
     * Testing isArrayPrimitiveEqual with the same arrays.
     */
    @Test
    void isArrayPrimitiveEqual_sameArraysTest() {
        assertTrue(ArrayUtilities.isArrayPrimativeEqual(new int[]{1, 2, 3}, new int[]{1, 2, 3}));
    }

    /**
     * Testing first part of first branch of arrayRangesEquals().
     */
    @Test
    void arrayRangesEquals_lenIsLargerThan_b1Test() {
        byte[] b1 = {0, 1, 2, 3};
        byte[] b2 = {0, 1, 2, 3};
        assertFalse(ArrayUtilities.arrayRangesEquals(b1, 3, b2, 0, 2));
    }

    /**
     * Testing second part of first branch of arrayRangesEquals().
     */
    @Test
    void arrayRangesEquals_lenIsLargerThan_b2Test() {
        byte[] b1 = {0, 1, 2, 3};
        byte[] b2 = {0, 1, 2, 3};
        assertFalse(ArrayUtilities.arrayRangesEquals(b1, 0, b2, 3, 2));
    }

    /**
     * Testing arrayRangesEquals() with different arrays.
     */
    @Test
    void arrayRangesEquals_differentArraysTest() {
        byte[] b1 = {0, 1, 2, 3};
        byte[] b2 = {4, 5, 6, 7};
        assertFalse(ArrayUtilities.arrayRangesEquals(b1, 0, b2, 0, 3));
    }

    /**
     * Testing arrayRangesEquals() with same arrays but different ranges.
     */
    @Test
    void arrayRangesEquals_differentRangesTest() {
        byte[] b1 = {0, 1, 2, 3};
        byte[] b2 = {0, 1, 2, 3};
        assertFalse(ArrayUtilities.arrayRangesEquals(b1, 1, b2, 0, 2));
    }

    /**
     * Testing arrayRangesEquals() with same arrays and ranges.
     */
    @Test
    void arrayRangesEqualsTest() {
        byte[] b1 = {0, 1, 2, 3};
        byte[] b2 = {0, 1, 2, 3};
        assertTrue(ArrayUtilities.arrayRangesEquals(b1, 1, b2, 1, 2));
    }

    /**
     * Testing if copyAndAppend() returns a copy of the same array with an additional element.
     * Asserts check if the length of the returned array is the same as the expected array and if
     * all elements are the same.
     */
    @Test
    void copyAndAppendTest() {
        Integer[] array = {0, 1, 2, 3, 4, 5};
        int[] expectedCopyWithNewElement = {0, 1, 2, 3, 4, 5, 6};

        Integer[] returnedArray = ArrayUtilities.copyAndAppend(array, 6);

        assertEquals(expectedCopyWithNewElement.length, returnedArray.length);

        for(int i = 0; i < expectedCopyWithNewElement.length; i++) {
            assertEquals(expectedCopyWithNewElement[i], returnedArray[i]);
        }

    }

    /**
     * Testing first branch of compare().
     */
    @Test
    void compare_arraysDifferentLengthsTest() {
        byte[] a = {0, 1, 2, 3};
        byte[] b = {0, 1, 2, 3, 4};

        assertEquals(a.length - b.length, ArrayUtilities.compare(a, b));
    }

    /**
     * Testing compare() with different arrays.
     */
    @Test
    void compare_arraysDifferentArraysTest() {
        byte[] a = {0, 1, 2, 3};
        byte[] b = {0, 1, 6, 7};

        assertEquals(a[2] - b[2], ArrayUtilities.compare(a, b));
    }

    /**
     * Testing compare() with same arrays.
     */
    @Test
    void compareTest() {
        byte[] a = {0, 1, 2, 3};
        byte[] b = {0, 1, 2, 3};

        assertEquals(0, ArrayUtilities.compare(a, b));
    }
}
