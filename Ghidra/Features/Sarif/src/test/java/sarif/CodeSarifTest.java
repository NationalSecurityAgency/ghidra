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
package sarif;

import org.junit.Test;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.util.ProgramDiff;
import sarif.managers.CodeSarifMgr;

public class CodeSarifTest extends AbstractSarifTest
{
	public CodeSarifTest() {
		super();
	}

	@Test
    public void testBasic() throws Exception {
		readWriteCompare();
	}
	
	@Test
    public void testCodeUnits() throws Exception {	
		block.putBytes(entry, asm, 0, asm.length);
		ProgramDiff programDiff = readWriteCompare();
		assert(programDiff.memoryMatches());
	}
	
	@Test
    public void testInstructions() throws Exception {	
		block.putBytes(entry, asm, 0, asm.length);
		MessageLog log = new MessageLog();
		CodeSarifMgr mgr = new CodeSarifMgr(program, log);
		AddressSet set = new AddressSet();
		AddressRangeIterator addressRanges = program.getMemory().getAddressRanges();
		for (AddressRange r : addressRanges) {
			set.add(r);
		}
		mgr.disassemble(set, monitor);
		
		ProgramDiff programDiff = readWriteCompare();
		assert(programDiff.memoryMatches());
	}
	
	@Test
    public void testData() throws Exception {	
		block.putBytes(entry, asm, 0, asm.length);
		program.getListing().createData(entry, new ByteDataType());
		program.getListing().createData(entry.add(instOffsets[1]), new ShortDataType());
		program.getListing().createData(entry.add(instOffsets[2]), new WordDataType());
		program.getListing().createData(entry.add(instOffsets[3]), new DWordDataType());
		
		ProgramDiff programDiff = readWriteCompare();
		assert(programDiff.memoryMatches());
	}
	
}
