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
package ghidra.bitpatterns.info;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import generic.jar.ResourceFile;
import generic.test.AbstractGenericTest;
import ghidra.bitpatterns.gui.ClosedPatternRowObject;
import ghidra.framework.Application;

public class ClosedPatternRowObjectTest extends AbstractGenericTest {

	private FileBitPatternInfoReader fReader;

	@Before
	public void setUp() throws IOException {
		ResourceFile resourceFile = Application.getModuleDataSubDirectory("BytePatterns", "test");
		fReader = new FileBitPatternInfoReader(resourceFile.getFile(false));
	}

	@Test
	public void testMiningFirstPatternsCharacters() {
		List<FunctionBitPatternInfo> fInfo = fReader.getFInfoList();
		ByteSequenceLengthFilter lFilter = new ByteSequenceLengthFilter(5, 5);
		List<ByteSequenceRowObject> firstBytes =
			ByteSequenceRowObject.getFilteredRowObjects(fInfo, PatternType.FIRST, null, lFilter);
		assertEquals(3, firstBytes.size());
		List<ClosedPatternRowObject> closedRows = ClosedPatternRowObject.mineClosedPatterns(
			firstBytes, 0.1, 16, false, PatternType.FIRST, null, null);
		assertEquals(4, closedRows.size());
		for (ClosedPatternRowObject row : closedRows) {
			switch (row.getDittedString()) {
				case "0x55 0x48 0x89 0xe5 ........":
					assertEquals(32, row.getNumFixedBits());
					assertEquals(32, row.getNumOccurrences());
					break;
				case "0x55 0x48 0x89 0xe5 0x48":
					assertEquals(40, row.getNumFixedBits());
					assertEquals(22, row.getNumOccurrences());
					break;
				case "0x55 0x48 0x89 0xe5 0x89":
					assertEquals(40, row.getNumFixedBits());
					assertEquals(6, row.getNumOccurrences());
					break;
				case "0x55 0x48 0x89 0xe5 0x53":
					assertEquals(40, row.getNumFixedBits());
					assertEquals(4, row.getNumOccurrences());
					break;
				default:
					fail();
			}
		}
	}

	@Test
	public void testMiningFirstPatternsBinary() {
		List<FunctionBitPatternInfo> fInfo = fReader.getFInfoList();
		ByteSequenceLengthFilter lFilter = new ByteSequenceLengthFilter(5, 5);
		List<ByteSequenceRowObject> firstBytes =
			ByteSequenceRowObject.getFilteredRowObjects(fInfo, PatternType.FIRST, null, lFilter);
		assertEquals(3, firstBytes.size());
		List<ClosedPatternRowObject> closedRows = ClosedPatternRowObject.mineClosedPatterns(
			firstBytes, 0.25, 16, true, PatternType.FIRST, null, null);
		assertEquals(5, closedRows.size());
		for (ClosedPatternRowObject row : closedRows) {
			switch (row.getDittedString()) {
				case "0x55 0x48 0x89 0xe5 ..0..0..":
					assertEquals(34, row.getNumFixedBits());
					assertEquals(32, row.getNumOccurrences());
					break;
				case "0x55 0x48 0x89 0xe5 ..00100.":
					assertEquals(37, row.getNumFixedBits());
					assertEquals(28, row.getNumOccurrences());
					break;
				case "0x55 0x48 0x89 0xe5 010..0..":
					assertEquals(36, row.getNumFixedBits());
					assertEquals(26, row.getNumOccurrences());
					break;
				case "0x55 0x48 0x89 0xe5 0x48":
					assertEquals(40, row.getNumFixedBits());
					assertEquals(22, row.getNumOccurrences());
					break;
				case "0x55 0x48 0x89 0xe5 ..0..0.1":
					assertEquals(35, row.getNumFixedBits());
					assertEquals(10, row.getNumOccurrences());
					break;
				default:
					fail();
			}
		}
	}
}
