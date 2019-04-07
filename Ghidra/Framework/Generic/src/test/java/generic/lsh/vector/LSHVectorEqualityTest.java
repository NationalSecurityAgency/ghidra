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
package generic.lsh.vector;

import org.junit.*;

/**
 * This class tests equality calculations of the {@link LSHVector} class.
 */
public class LSHVectorEqualityTest {

	// Define two vectors we'll compare in each of the tests.
	LSHCosineVector vec1;
	LSHCosineVector vec2;

	// Also define some hash entries that we can populate the vectors with. 
	HashEntry entry1;
	HashEntry entry2;
	HashEntry entry3;
	HashEntry entry4;
	HashEntry entry5;
	HashEntry entry6;
	HashEntry entry7;
	HashEntry entry8;
	HashEntry entry9;
	HashEntry entry10;
	HashEntry entry11;

	/**
	 * Creates data objects for use in all tests.
	 * 
	 * @see HashEntry
	 * @throws Exception
	 */
	@Before
	public void setUp() throws Exception {
		vec1 = new LSHCosineVector();
		vec2 = new LSHCosineVector();

		// Create the test hashes. Note that the first two are the same - this is by design so 
		// we can verify that our equality tests will handle objects that are distinct but have
		// identical internal values.
		entry1 = new HashEntry(1, 2, 3.0);
		entry2 = new HashEntry(1, 2, 3.0);
		entry3 = new HashEntry(4, 5, 6.0);
		entry4 = new HashEntry(7, 8, 9.0);
		entry5 = new HashEntry(7, 8, 9.1);
		entry6 = new HashEntry(7, 64, 9.1);// tcnt > 63 causes TF value to change
		entry7 = new HashEntry(8, 64, 9.1);// tcnt > 63 causes TF value to change

		// Create a few entries that use the WeightFactory constructor for HashEntry; this allows
		// us to change the IDF value and verify that our equality checks still work.
		WeightFactory w = new WeightFactory();
		entry8 = new HashEntry(1, 2, 3, w);
		entry9 = new HashEntry(1, 2, 3, w);
		entry10 = new HashEntry(1, 2, 512, w);// dcnt > 511 causes IDF value to change
	}

	@After
	public void tearDown() throws Exception {
		// nothing to do
	}

	/**
	 * Test:
	 *   1. Hash arrays are null
	 *   
	 * Expected Result: EQUAL
	 */
	@Test
	public void testEquality1() {
		Assert.assertTrue("failed to equate two empty vectors", vec1.equals(vec2));
	}

	/**
	 * Test:
	 *   1. Hash arrays are the same size
	 *   2. Elements are NULL
	 *   
	 * Expected Result: EQUAL
	 */
	@Test
	public void testEquality2() {

		HashEntry[] hashEntries1 = new HashEntry[5];
		HashEntry[] hashEntries2 = new HashEntry[5];
		vec1.setHashEntries(hashEntries1);
		vec2.setHashEntries(hashEntries2);
		Assert.assertTrue("failed to equate two vectors with identical HashEntry instances",
			vec1.equals(vec2));
	}

	/**
	 * Test:
	 *   1. Hash arrays are different sizes
	 *   2. Elements are NULL
	 *   
	 * Expected Result: NOT EQUAL
	 */
	@Test
	public void testEquality3() {

		HashEntry[] hashEntries1 = new HashEntry[5];
		HashEntry[] hashEntries2 = new HashEntry[6];
		vec1.setHashEntries(hashEntries1);
		vec2.setHashEntries(hashEntries2);
		Assert.assertFalse(
			"failed to distinguish between vectors with different hash entry array sizes",
			vec1.equals(vec2));
	}

	/**
	 * Test:
	 *   1. Hash arrays are the same size
	 *   2. Hash arrays contain the same elements
	 *   3. Elements are in the same order
	 *   4. Elements contain the same values
	 *   
	 *   Note: entry1 and entry2 in this test contain the same values. This test is meant to 
	 *         verify that ordering does not matter in checking equality of the arrays, so the
	 *         contents of the hash entry elements is kept the same to remove that as a variable.
	 *   
	 * Expected Result: EQUAL
	 */
	@Test
	public void testEquality4() {

		HashEntry[] hashEntries1 = new HashEntry[] { entry1, entry2 };
		HashEntry[] hashEntries2 = new HashEntry[] { entry1, entry2 };
		vec1.setHashEntries(hashEntries1);
		vec2.setHashEntries(hashEntries2);
		Assert.assertTrue("failed to equate vectors with identical hash entries",
			vec1.equals(vec2));
	}

	/**
	 * Test:
	 *   1. Hash arrays are the same size
	 *   2. Hash arrays contain the same elements 
	 *   3. Elements are NOT in the same order
	 *   4. Elements contain the same values
	 *   
	 *   Note: entry1 and entry2 in this test contain the same values. This test is meant to 
	 *         verify that ordering does not matter in checking equality of the arrays, so the
	 *         contents of the hash entry elements is kept the same to remove that as a variable.
	 *   
	 * Expected Result: EQUAL
	 */
	@Test
	public void testEquality5() {

		HashEntry[] hashEntries1 = new HashEntry[] { entry1, entry2 };
		HashEntry[] hashEntries2 = new HashEntry[] { entry2, entry1 };
		vec1.setHashEntries(hashEntries1);
		vec2.setHashEntries(hashEntries2);
		Assert.assertTrue("failed to equate vectors with identical elements in different order",
			vec1.equals(vec2));
	}

	/**
	 * Test:
	 *   1. Hash arrays are the same size
	 *   2. Hash arrays contain the same elements 
	 *   3. Elements are in the same order
	 *   4. Elements do NOT contain the same values
	 *   
	 * Expected Result: EQUAL
	 *   
	 */
	@Test
	public void testEquality6() {

		HashEntry[] hashEntries1 = new HashEntry[] { entry1, entry3 };
		HashEntry[] hashEntries2 = new HashEntry[] { entry1, entry3 };
		vec1.setHashEntries(hashEntries1);
		vec2.setHashEntries(hashEntries2);
		Assert.assertTrue("failed to equate vectors with identical hash entries with same ordering",
			vec1.equals(vec2));
	}

	/**
	 * Test:
	 *   1. Hash arrays same size
	 *   2. Hash arrays contain same elements
	 *   3. Elements are NOT in the same order
	 *   4. Elements do NOT contain the same values
	 *   
	 * Expected Result: NOT EQUAL
	 *   
	 */
	@Test
	public void testEquality7() {

		HashEntry[] hashEntries1 = new HashEntry[] { entry1, entry3 };
		HashEntry[] hashEntries2 = new HashEntry[] { entry3, entry1 };
		vec1.setHashEntries(hashEntries1);
		vec2.setHashEntries(hashEntries2);
		Assert.assertFalse("failed to recognize that vector elements are not in the same order",
			vec1.equals(vec2));
	}

	/**
	 * Test:
	 *   1. Hash arrays same size
	 *   2. Hash arrays contain different elements
	 *   
	 * Expected Result: NOT EQUAL
	 *   
	 */
	@Test
	public void testEquality8() {

		HashEntry[] hashEntries1 = new HashEntry[] { entry1, entry2 };
		HashEntry[] hashEntries2 = new HashEntry[] { entry1, entry3 };
		vec1.setHashEntries(hashEntries1);
		vec2.setHashEntries(hashEntries2);
		Assert.assertFalse("failed to distinguish between vectors with different hash entries",
			vec1.equals(vec2));
	}

	/**
	 * Test:
	 *   1. Hash arrays different size
	 *   
	 * Expected Result: NOT EQUAL
	 *   
	 */
	@Test
	public void testEquality9() {

		HashEntry[] hashEntries1 = new HashEntry[] { entry1, entry2 };
		HashEntry[] hashEntries2 = new HashEntry[] { entry1, entry1, entry2 };
		vec1.setHashEntries(hashEntries1);
		vec2.setHashEntries(hashEntries2);
		Assert.assertFalse("failed to distinguish between different size vectors",
			vec1.equals(vec2));
	}

	/**
	 * Test:
	 *   1. Hash arrays are identical except for the {@link HashEntry#getCoeff()} value. These vectors should
	 *   still be considered equal.
	 *   
	 * Expected Result: EQUAL
	 *   
	 */
	@Test
	public void testEquality10() {

		HashEntry[] hashEntries1 = new HashEntry[] { entry4 };
		HashEntry[] hashEntries2 = new HashEntry[] { entry5 };
		vec1.setHashEntries(hashEntries1);
		vec2.setHashEntries(hashEntries2);
		Assert.assertTrue(
			"failed to recognize equivalent vectors WEIGHT value is different",
			vec1.equals(vec2));
	}

	/**
	 * Test:
	 *   1. Hash arrays are identical except for the {@link HashEntry#getTF()} value.
	 *   
	 * Expected Result: NOT EQUAL
	 *   
	 */
	@Test
	public void testEquality11() {

		HashEntry[] hashEntries1 = new HashEntry[] { entry5 };
		HashEntry[] hashEntries2 = new HashEntry[] { entry6 };
		vec1.setHashEntries(hashEntries1);
		vec2.setHashEntries(hashEntries2);
		Assert.assertFalse(
			"failed to distinguish between vectors when only the TF value is different",
			vec1.equals(vec2));
	}

	/**
	 * Test:
	 *   1. Hash arrays are identical except for the {@link HashEntry#getCoeff()} value.
	 *   
	 * Expected Result: NOT EQUAL
	 *   
	 */
	@Test
	public void testEquality12() {

		HashEntry[] hashEntries1 = new HashEntry[] { entry6 };
		HashEntry[] hashEntries2 = new HashEntry[] { entry7 };
		vec1.setHashEntries(hashEntries1);
		vec2.setHashEntries(hashEntries2);
		Assert.assertFalse(
			"failed to distinguish between vectors when only the COEFF value is different",
			vec1.equals(vec2));
	}

	/**
	 * Test:
	 *   1. Elements contain the same IDF values calculated by {@link WeightFactory}
	 *   
	 * Expected Result: EQUAL
	 *   
	 */
	@Test
	public void testEquality13() {

		HashEntry[] hashEntries1 = new HashEntry[] { entry8 };
		HashEntry[] hashEntries2 = new HashEntry[] { entry9 };
		vec1.setHashEntries(hashEntries1);
		vec2.setHashEntries(hashEntries2);
		Assert.assertTrue(
			"failed to equate vectors with identical hash entries using WeightFactory",
			vec1.equals(vec2));
	}

	/**
	 * Test:
	 *   1. Elements contain different IDF values calculated by {@link WeightFactory}
	 *   
	 * Expected Result: NOT EQUAL
	 *   
	 */
	@Test
	public void testEquality14() {

		HashEntry[] hashEntries1 = new HashEntry[] { entry10 };
		HashEntry[] hashEntries2 = new HashEntry[] { entry11 };
		vec1.setHashEntries(hashEntries1);
		vec2.setHashEntries(hashEntries2);
		Assert.assertFalse(
			"failed to distinguish between vectors when only the IDF value is different",
			vec1.equals(vec2));
	}
}
