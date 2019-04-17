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
package ghidra.app.util.cparser.C;

import static org.junit.Assert.assertTrue;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class CParserUtilsTest extends AbstractGenericTest {

	public CParserUtilsTest() {
		super();
	}

	@Test
    public void testUserMessage_OnTokenMgrError() {
		String function = "void bob@12(int a)";
		Throwable t = getParseError(function);
		String message = CParserUtils.handleParseProblem(t, function);

		String characterInfo = "near character 8";
		String invalidInfo = "<font color=\"red\"><b>@";
		assertTrue(message.contains(characterInfo));
		assertTrue(message.contains(invalidInfo));
	}

	@Test
    public void testUserMessage_OnParseException() {
		String function = "void bob(int a)()";
		Throwable t = getParseError(function);
		String message = CParserUtils.handleParseProblem(t, function);

		String characterInfo = "near character 17";
		assertTrue(message.contains(characterInfo));
	}

	private Throwable getParseError(String function) {
		CParser parser = new CParser();
		try {
			parser.parse(function);
		}
		catch (Throwable t) {
			return t;
		}
		Assert.fail("Funcion text did not trigger a parse problem: " + function);
		return null;// can't get here
	}
}
