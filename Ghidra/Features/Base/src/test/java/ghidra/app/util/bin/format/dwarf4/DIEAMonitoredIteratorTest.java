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
package ghidra.app.util.bin.format.dwarf4;

import static ghidra.app.util.bin.format.dwarf4.encoding.DWARFAttribute.DW_AT_name;
import static ghidra.app.util.bin.format.dwarf4.encoding.DWARFAttribute.DW_AT_type;

import java.io.IOException;

import org.junit.Assert;
import org.junit.Test;

import ghidra.app.util.bin.format.dwarf4.encoding.DWARFTag;
import ghidra.app.util.bin.format.dwarf4.next.DIEAMonitoredIterator;
import ghidra.util.exception.CancelledException;

public class DIEAMonitoredIteratorTest extends DWARFTestBase {

	@Test
	public void testForwardCrossCURef() throws CancelledException, DWARFException, IOException {
		DebugInfoEntry cu2Int = addInt(cu2);
		new DIECreator(DWARFTag.DW_TAG_typedef).addString(DW_AT_name, "forward").addRef(DW_AT_type,
			cu2Int.getOffset()).create(cu);

		dwarfProg.getImportOptions().setPreloadAllDIEs(true);
		checkPreconditions();

		int count = 0;
		for (DIEAggregate diea : DIEAMonitoredIterator.iterable(dwarfProg, "Testing", monitor)) {
			count++;
		}
		Assert.assertEquals(4, count);
	}

	@Test
	public void testNormalIteration() throws CancelledException, DWARFException, IOException {
		addFloat(cu);
		addInt(cu2);

		checkPreconditions();

		int count = 0;
		for (DIEAggregate diea : DIEAMonitoredIterator.iterable(dwarfProg, "Testing", monitor)) {
			count++;
		}
		Assert.assertEquals(4, count);
	}

	@Test
	public void testCrossCUAggregate() throws CancelledException, DWARFException, IOException {
		DebugInfoEntry cu1Struct = newDeclStruct("mystruct").create(cu);
		DebugInfoEntry cu2Struct = newSpecStruct(cu1Struct, 10).create(cu2);

		dwarfProg.getImportOptions().setPreloadAllDIEs(true);

		checkPreconditions();

		int count = 0;
		for (DIEAggregate diea : DIEAMonitoredIterator.iterable(dwarfProg, "Testing", monitor)) {
			count++;
		}

		DIEAggregate diea = getAggregate(cu2Struct);
		Assert.assertEquals(2, diea.getFragmentCount());
		Assert.assertEquals(3, dwarfProg.getTotalAggregateCount());
		Assert.assertEquals(3, count);
	}

	@Test
	public void testCrossCUAggregate2() throws CancelledException, DWARFException, IOException {
		DebugInfoEntry cu1Struct = newDeclStruct("mystruct").create(cu);
		addFloat(cu);
		addDouble(cu);
		DebugInfoEntry cu2Struct = newSpecStruct(cu1Struct, 10).create(cu2);
		addFloat(cu2);
		addDouble(cu2);

		dwarfProg.getImportOptions().setPreloadAllDIEs(true);

		checkPreconditions();

		int count = 0;
		for (DIEAggregate diea : DIEAMonitoredIterator.iterable(dwarfProg, "Testing", monitor)) {
			count++;
		}

		DIEAggregate diea = getAggregate(cu2Struct);
		Assert.assertEquals(2, diea.getFragmentCount());
		Assert.assertEquals(7, dwarfProg.getTotalAggregateCount());
		Assert.assertEquals(7, count);
	}
}
