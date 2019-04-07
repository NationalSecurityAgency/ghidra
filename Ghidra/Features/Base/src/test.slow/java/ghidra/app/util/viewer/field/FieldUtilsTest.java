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
package ghidra.app.util.viewer.field;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

import docking.widgets.fieldpanel.support.FieldUtils;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

public class FieldUtilsTest extends AbstractGhidraHeadedIntegrationTest {

	private Program program;

	private ProgramDB buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY, this);

		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createLabel("1001000", "ADVAPI32.dll_IsTextUnicode");
		builder.createLabel("1001014", "bob");

		return builder.getProgram();
	}

	@Before
	public void setUp() throws Exception {
		program = buildProgram();
	}

	@Test
	public void testGetDisplayString() throws Exception {

		// test no text
		String data = "";
		String displayText = CommentUtils.getDisplayString(data, program);
		assertEquals("", displayText);

		// test single annotation
		data = "This is an annotated string {@symbol 01001000}";
		displayText = CommentUtils.getDisplayString(data, program);
		assertEquals("This is an annotated string ADVAPI32.dll_IsTextUnicode", displayText);
	}

	@Test
	public void testLabelTrimming() {
		String string = "foo";
		String trimmedString = FieldUtils.trimString(string);
		assertEquals("foo", trimmedString);

		string = "[foo]";
		trimmedString = FieldUtils.trimString(string);
		assertEquals("foo", trimmedString);

		string = " foo ";
		trimmedString = FieldUtils.trimString(string);
		assertEquals("foo", trimmedString);

		string = "[ foo] ";
		trimmedString = FieldUtils.trimString(string);
		assertEquals("foo", trimmedString);

		string = " ] [ foo ] [  ] ";
		trimmedString = FieldUtils.trimString(string);
		assertEquals("foo", trimmedString);

		string = "_foo_";
		trimmedString = FieldUtils.trimString(string);
		assertEquals("_foo_", trimmedString);

		string = " _foo_ ";
		trimmedString = FieldUtils.trimString(string);
		assertEquals("_foo_", trimmedString);

		string = "_ foo_ ";
		trimmedString = FieldUtils.trimString(string);
		assertEquals("_", trimmedString);

		string = "foo[89]";
		trimmedString = FieldUtils.trimString(string);
		assertEquals("foo", trimmedString);

		string = "foo[EAX]";
		trimmedString = FieldUtils.trimString(string);
		assertEquals("foo", trimmedString);

		string = "foo[";
		trimmedString = FieldUtils.trimString(string);
		assertEquals("foo", trimmedString);
	}

	// used for debug while developing tests
//    private void printAttributedStrings( FieldElement[] attributedStrings ) {
//        System.err.println( "AttributedStrings: ");
//        for (int i = 0; i < attributedStrings.length; i++) {
//            System.err.println( ":: " + attributedStrings[i].getText() );
//        }
//    }
}
