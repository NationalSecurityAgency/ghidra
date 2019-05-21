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
package generic.algorithms;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.junit.Test;

public class ReducingLCSTest {

	@Test
	public void testIdentical() {
		compareStrings("DEADBEEF", "DEADBEEF", "DEADBEEF");
	}

	@Test
	public void testSimilar() {
		compareStrings("DEADBEEF", "DEEDBEAD", "DEDBE");
		compareStrings(
			"Some really long string that might complicate things." +
				"Hooray for really long strings that span multiple lines!",
			"Some other really long string that might complicate things." +
				"Hooray for really loooooong strings that span multiple lines in java!",
			"Some really long string that might complicate things." +
				"Hooray for really long strings that span multiple lines!");
	}

	@Test
	public void testDifferent() {

		compareStrings("DEAD", "CANND", "AD");
		compareStrings("DEADBEEFISGOOD", "CANNDBEEFISBAD", "ADBEEFISD");
		compareStrings("this here is one string", "here a different string is", "here in string");
	}

	@Test
	public void testInsertOnly() {

		String x = "Line not modified";
		String y = "Line not not modified";
		compareStrings(x, y, x);
	}

	@Test
	public void testRemovalOnly() {

		String x = "Line not modified";
		String y = "Line modified";
		compareStrings(x, y, y);
	}

	@Test
	public void testSizeLimit() {

		String x = "This is a line that has not been modified";
		String y = "This is a line that has been modified";

		StringLcs slcs = new StringLcs(x, y);
		slcs.setSizeLimit(10);
		List<Character> lcs = slcs.getLcs();
		String result = StringUtils.join(lcs, "");
		assertEquals(y, result); // 'y' is common, since it is 'x', with only a delete

		String z = "Start Mod " + x + " End Mod"; // same as 'x', but with different start/end
		slcs = new StringLcs(x, z);
		slcs.setSizeLimit(10);
		List<Character> actual = slcs.getLcs();
		assertTrue(actual.isEmpty());
	}

	private void compareStrings(String x, String y, String expected) {
		StringLcs slcs = new StringLcs(x, y);
		List<Character> actual = slcs.getLcs();
		assertEquals(convertString(expected), actual);
	}

	private List<Character> convertString(String s) {
		List<Character> charList = new ArrayList<>();
		for (char c : s.toCharArray()) {
			charList.add(c);
		}
		return charList;
	}

	private class StringLcs extends ReducingLcs<String, Character> {

		public StringLcs(String x, String y) {
			super(x, y);
		}

		@Override
		protected String reduce(String input, int start, int end) {
			return input.substring(start, end);
		}

		@Override
		protected int lengthOf(String s) {
			return s.length();
		}

		@Override
		protected Character valueOf(String s, int offset) {
			return s.charAt(offset);
		}
	}
}
