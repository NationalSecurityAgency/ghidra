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
package ghidra.util.datastruct;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class AlphaNumericComparatorTest extends AbstractGenericTest {

	@Test
	public void testCaseSensitive() {

		List<String> unsorted = Arrays.asList(

			"  file10",       // Leading spaces
			"file02  ",       // Trailing spaces
			"file  2",        // Internal spaces
			"file1",          // Normal  
			"  file002  ",    // Leading and trailing spaces
			"file 01",        // Internal space before digit
			"file20",

			"  apple",        // Leading spaces
			"Apple  ",        // Trailing spaces
			"ba  nana",       // Internal spaces
			"a",
			"alpha  ",        // Trailing spaces
			"  alphabet",     // Leading spaces
			"app",
			"ap  ple",         // Internal spaces

			"0.1.0",
			"0.1.9",
			"1.0",
			"0.2.1",
			"2.1.0");

		List<String> sorted = Arrays.asList(
			"0.1.0",
			"0.1.9",
			"0.2.1",
			"1.0",
			"2.1.0",
			"Apple  ",
			"a",
			"alpha  ",
			"  alphabet",
			"app",
			"  apple",
			"ap  ple",
			"ba  nana",
			"file1",
			"file 01",
			"file  2",
			"file02  ",
			"  file002  ",
			"  file10",
			"file20");

		Collections.shuffle(unsorted);
		List<String> copy = new ArrayList<>(unsorted);
		Collections.sort(copy, new AlphaNumericComparator());

		assertEquals(sorted, copy);
	}

	@Test
	public void testCaseInsensitive() {

		List<String> unsorted = Arrays.asList(

			"  file10",       // Leading spaces
			"file02  ",       // Trailing spaces
			"file  2",        // Internal spaces
			"file1",          // Normal  
			"  file002  ",    // Leading and trailing spaces
			"file 01",        // Internal space before digit
			"file20",

			"  apple",        // Leading spaces
			"Apple  ",        // Trailing spaces
			"ba  nana",       // Internal spaces
			"a",
			"alpha  ",        // Trailing spaces
			"  alphabet",     // Leading spaces
			"app",
			"ap  ple",         // Internal spaces

			"0.1.0",
			"0.1.9",
			"1.0",
			"0.2.1",
			"2.1.0");

		List<String> sorted = Arrays.asList(
			"0.1.0",
			"0.1.9",
			"0.2.1",
			"1.0",
			"2.1.0",
			"a",
			"alpha  ",
			"  alphabet",
			"app",
			"  apple",
			"Apple  ",
			"ap  ple",
			"ba  nana",
			"file1",
			"file 01",
			"file  2",
			"file02  ",
			"  file002  ",
			"  file10",
			"file20");

		Collections.shuffle(unsorted);
		List<String> copy = new ArrayList<>(unsorted);
		Collections.sort(copy, new AlphaNumericComparator(false));

		assertEquals(sorted, copy);
	}
}
