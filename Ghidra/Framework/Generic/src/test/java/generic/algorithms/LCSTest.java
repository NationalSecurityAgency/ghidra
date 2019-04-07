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

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class LCSTest extends AbstractGenericTest {

	public LCSTest() {
		super();

	}

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

	private void compareStrings(String x, String y, String expected) {
		StringLCS slcs = new StringLCS(x, y);
		List<Character> actual = slcs.getLCS();

		assertEquals(convertString(expected), actual);
	}

	private List<Character> convertString(String s) {
		List<Character> charList = new ArrayList<Character>();
		for (char c : s.toCharArray())
			charList.add(c);
		return charList;
	}

	private class StringLCS extends LCS<Character> {

		private String x;
		private String y;

		public StringLCS(String x, String y) {
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
