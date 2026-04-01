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
package ghidra.app.util.viewer.listingpanel;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.framework.options.SaveState;
import ghidra.framework.options.ToolOptions;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;

public class ProgramBigListingModelOpenDataTest extends AbstractGenericTest {

	private ProgramDB program;
	private ProgramBigListingModel model;
	private AddressSpace space;

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._X86);
		program = builder.getProgram();
		space = program.getAddressFactory().getDefaultAddressSpace();
		builder.createMemory("block1", "0", 100);

		FormatManager formatManager =
			new FormatManager(new ToolOptions("display"), new ToolOptions("Listing Fields"));
		formatManager.readState(new SaveState()); // this will use default format
		model = new ProgramBigListingModel(program, formatManager);
		
		StructureDataType struct1 = new StructureDataType("aaa", 4);
		StructureDataType struct2 = new StructureDataType("bbb", 2);
		UnionDataType union = new UnionDataType("uuu");
		union.add(struct1);
		union.add(struct2);
		builder.applyDataType("0", union);
			
	
	}


	private Address addr(long offset) {
		return space.getAddress(offset);
	}

	@Test
	public void testGetPreviousAddressWithLargerUnionComponentOpen() {
		Listing listing = program.getListing();
		Data data = listing.getDataAt(addr(0));
		Data component = data.getComponent(0);
		model.openData(component);
		assertEquals(addr(2), model.getAddressBefore(addr(3)));
	}
	@Test
	public void testGetPreviousAddressWithSmallerUnionComponentOpen() {
		Listing listing = program.getListing();
		Data data = listing.getDataAt(addr(0));
		Data component = data.getComponent(1);
		model.openData(component);
		assertEquals(addr(2), model.getAddressBefore(addr(3)));
	}

}
