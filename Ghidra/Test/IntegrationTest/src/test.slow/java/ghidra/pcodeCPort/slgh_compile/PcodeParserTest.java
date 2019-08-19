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
package ghidra.pcodeCPort.slgh_compile;

import static org.junit.Assert.*;

import java.io.*;
import java.util.List;

import org.junit.Test;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.sleigh.grammar.Location;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class PcodeParserTest extends AbstractGhidraHeadlessIntegrationTest {

	private void compare(String actual, String expectedFilename) throws IOException {

		List<String> expectedList = loadTextResource(getClass(), expectedFilename);

		BufferedReader actualRdr = new BufferedReader(new StringReader(actual));

		for (String expectedLine : expectedList) {
			String actualLine = actualRdr.readLine();
			assertEquals(expectedLine, actualLine);
		}

		assertNull(actualRdr.readLine());
	}

	@Test
	public void testCompilePcode() throws Exception {

		SleighLanguage lang = (SleighLanguage) getSLEIGH_X86_LANGUAGE();

		long uniqueBase = 0x1000000; // make sure we avoid the decompiler range
		String sleighSpec =
			lang.buildTranslatorTag(lang.getAddressFactory(), uniqueBase, lang.getSymbolTable());

		String pcodeStatements = "tmp:1 = inst_next;\n" + "if (AX == 0) goto inst_next;\n" +
			"call [ECX];\n" + "if (BX != 1) goto <lab>;\n" + "CX = 0;\n" + "<lab>\n" +
			"BX = CX << 2;\n" + "in1 = in2 + 7;";

		PcodeParser parser = new PcodeParser(sleighSpec);
		Location loc = new Location("pcodetest", 5);
		parser.addOperand(loc, "in1", 0);
		parser.addOperand(loc, "in2", 1);
		String contructTplXml =
			PcodeParser.stringifyTemplate(parser.compilePcode(pcodeStatements, "test", 200));
		assertNotNull("Pcode compile failed (see log)", contructTplXml);
		compare(contructTplXml, "pcode1.xml");
	}
}
