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

import generic.test.AbstractGenericTest;

public class LCSTest extends AbstractGenericTest {

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
	public void testSizeLimit() {

		String input = "This is more than 5 characters";
		StringLcs slcs = new StringLcs(input, input);
		List<Character> lcs = slcs.getLcs();
		String result = StringUtils.join(lcs, "");
		assertEquals(input, result);

		slcs = new StringLcs(input, input);
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

	private class StringLcs extends Lcs<Character> {

		private String x;
		private String y;

		public StringLcs(String x, String y) {
			super();
			this.x = x;
			this.y = y;
		}

		@Override
		protected int lengthOfX() {
			return x.length();
		}

		@Override
		protected int lengthOfY() {
			return y.length();
		}

		@Override
		protected boolean matches(Character myX, Character myY) {
			return myX.equals(myY);
		}

		@Override
		protected Character valueOfX(int index) {
			return x.charAt(index - 1);
		}

		@Override
		protected Character valueOfY(int index) {
			return y.charAt(index - 1);
		}
	}
}
