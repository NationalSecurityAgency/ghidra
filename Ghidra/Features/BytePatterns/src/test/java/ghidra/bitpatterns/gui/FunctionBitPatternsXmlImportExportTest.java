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
package ghidra.bitpatterns.gui;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.xml.sax.SAXException;

import generic.jar.ResourceFile;
import generic.test.AbstractGenericTest;
import ghidra.app.analyzers.FunctionStartAnalyzer;
import ghidra.bitpatterns.info.ContextRegisterFilter;
import ghidra.bitpatterns.info.PatternType;
import ghidra.util.bytesearch.*;

public class FunctionBitPatternsXmlImportExportTest extends AbstractGenericTest {

	@Test
	public void testRoundTrip() throws IOException, SAXException {
		List<PatternInfoRowObject> rows = new ArrayList<>();

		DittedBitSequence preSeq1 = new DittedBitSequence("0x00 0x01", true);
		PatternInfoRowObject pre1 = new PatternInfoRowObject(PatternType.PRE, preSeq1, null);
		rows.add(pre1);
		DittedBitSequence preSeq2 = new DittedBitSequence("0x00 0x02", true);
		PatternInfoRowObject pre2 = new PatternInfoRowObject(PatternType.PRE, preSeq2, null);
		rows.add(pre2);

		ContextRegisterFilter cRegFilter = new ContextRegisterFilter();
		cRegFilter.addRegAndValueToFilter("cReg", new BigInteger("1"));

		DittedBitSequence postSeq1 = new DittedBitSequence("0x00 0x03");
		PatternInfoRowObject post1 =
			new PatternInfoRowObject(PatternType.FIRST, postSeq1, cRegFilter);
		post1.setAlignment(4);
		rows.add(post1);

		DittedBitSequence postSeq2 = new DittedBitSequence("0x00 0x04");
		PatternInfoRowObject post2 =
			new PatternInfoRowObject(PatternType.FIRST, postSeq2, cRegFilter);
		post2.setAlignment(4);
		rows.add(post2);

		File xmlFile = createTempFile("PatternInfoXML");
		PatternInfoRowObject.exportXMLFile(rows, xmlFile, 16, 32);

		ResourceFile xmlResource = new ResourceFile(xmlFile);
		PatternPairSet patterns = ClipboardPanel.parsePatternPairSet(xmlResource);

		assertEquals(16, patterns.getPostBitsOfCheck());
		assertEquals(32, patterns.getTotalBitsOfCheck());

		assertEquals(2, patterns.getPreSequences().size());
		for (DittedBitSequence seq : patterns.getPreSequences()) {
			switch (seq.getHexString()) {
				case "0x00 0x01":
				case "0x00 0x02":
					break;
				default:
					fail();
			}
		}
		assertEquals(2, patterns.getPostPatterns().size());
		for (Pattern pat : patterns.getPostPatterns()) {
			switch (pat.getHexString()) {
				case "0x00 0x03":
				case "0x00 0x04":
					Assert.assertNotEquals(null, pat.getPostRules());
					assertEquals(1, pat.getPostRules().length);
					assertTrue(pat.getPostRules()[0] instanceof AlignRule);
					assertEquals(3, ((AlignRule) pat.getPostRules()[0]).getAlignMask());
					Assert.assertNotEquals(null, pat.getMatchActions());
					break;
				default:
					fail();
			}
		}
		//check that one of them has the correct match action
		boolean hasMatch = false;
		for (MatchAction match : patterns.getPostPatterns().get(0).getMatchActions()) {
			if (!(match instanceof FunctionStartAnalyzer.ContextAction)) {
				continue;
			}
			hasMatch = true;
			assertEquals("cReg", ((FunctionStartAnalyzer.ContextAction) match).getName());
			assertEquals(new BigInteger("1"),
				((FunctionStartAnalyzer.ContextAction) match).getValue());
		}
		assertTrue(hasMatch);
	}
}
