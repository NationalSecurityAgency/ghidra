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
import ghidra.program.model.listing.Function;

public class ProgramBigListingModelTest extends AbstractGenericTest {

	private ProgramDB program;
	private ProgramBigListingModel model;
	private AddressSpace space;

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._X86);
		program = builder.getProgram();
		space = program.getAddressFactory().getDefaultAddressSpace();
		builder.createMemory("block1", "0", 18);
		buildFun0(builder);

		FormatManager formatManager =
			new FormatManager(new ToolOptions("display"), new ToolOptions("Listing Fields"));
		formatManager.readState(new SaveState()); // this will use default format
		model = new ProgramBigListingModel(program, formatManager);
	}

	private void buildFun0(ProgramBuilder builder) throws OverlappingFunctionException {
		Function fun0 = builder.createFunction("0");
		AddressSet addrs = new AddressSet();
		addrs.add(addr(0), addr(3));
		addrs.add(addr(6), addr(9));
		addrs.add(addr(12), addr(15));
		program.withTransaction("test", () -> fun0.setBody(addrs));
	}

	private Address addr(long offset) {
		return space.getAddress(offset);
	}

	@Test
	public void testGetNextAddressWithFunctionOpen() {
		assertEquals(addr(1), model.getAddressAfter(addr(0)));
		assertEquals(addr(2), model.getAddressAfter(addr(1)));
		assertEquals(addr(3), model.getAddressAfter(addr(2)));
		assertEquals(addr(4), model.getAddressAfter(addr(3)));
		assertEquals(addr(5), model.getAddressAfter(addr(4)));
		assertEquals(addr(6), model.getAddressAfter(addr(5)));
		assertEquals(addr(7), model.getAddressAfter(addr(6)));
		assertEquals(addr(8), model.getAddressAfter(addr(7)));
		assertEquals(addr(9), model.getAddressAfter(addr(8)));
		assertEquals(addr(10), model.getAddressAfter(addr(9)));
		assertEquals(addr(11), model.getAddressAfter(addr(10)));
		assertEquals(addr(12), model.getAddressAfter(addr(11)));
		assertEquals(addr(13), model.getAddressAfter(addr(12)));
		assertEquals(addr(14), model.getAddressAfter(addr(13)));
		assertEquals(addr(15), model.getAddressAfter(addr(14)));
		assertEquals(addr(16), model.getAddressAfter(addr(15)));
		assertEquals(addr(17), model.getAddressAfter(addr(16)));
		assertNull(model.getAddressAfter(addr(17)));
	}

	@Test
	public void testGetNextAddressWithFunctionClosed() {
		model.setFunctionOpen(addr(0), false);

		assertEquals(addr(4), model.getAddressAfter(addr(0)));
		assertEquals(addr(4), model.getAddressAfter(addr(1)));
		assertEquals(addr(4), model.getAddressAfter(addr(2)));
		assertEquals(addr(4), model.getAddressAfter(addr(3)));
		assertEquals(addr(5), model.getAddressAfter(addr(4)));
		assertEquals(addr(6), model.getAddressAfter(addr(5)));
		assertEquals(addr(10), model.getAddressAfter(addr(6)));
		assertEquals(addr(10), model.getAddressAfter(addr(7)));
		assertEquals(addr(10), model.getAddressAfter(addr(8)));
		assertEquals(addr(10), model.getAddressAfter(addr(9)));
		assertEquals(addr(11), model.getAddressAfter(addr(10)));
		assertEquals(addr(12), model.getAddressAfter(addr(11)));
		assertEquals(addr(16), model.getAddressAfter(addr(12)));
		assertEquals(addr(16), model.getAddressAfter(addr(13)));
		assertEquals(addr(16), model.getAddressAfter(addr(14)));
		assertEquals(addr(16), model.getAddressAfter(addr(15)));
		assertEquals(addr(17), model.getAddressAfter(addr(16)));
		assertNull(model.getAddressAfter(addr(17)));
	}

	@Test
	public void testGetPreviousAddressWithFunctionOpen() {
		assertNull(model.getAddressBefore(addr(0)));
		assertEquals(addr(0), model.getAddressBefore(addr(1)));
		assertEquals(addr(1), model.getAddressBefore(addr(2)));
		assertEquals(addr(2), model.getAddressBefore(addr(3)));
		assertEquals(addr(3), model.getAddressBefore(addr(4)));
		assertEquals(addr(4), model.getAddressBefore(addr(5)));
		assertEquals(addr(5), model.getAddressBefore(addr(6)));
		assertEquals(addr(6), model.getAddressBefore(addr(7)));
		assertEquals(addr(7), model.getAddressBefore(addr(8)));
		assertEquals(addr(8), model.getAddressBefore(addr(9)));
		assertEquals(addr(9), model.getAddressBefore(addr(10)));
		assertEquals(addr(10), model.getAddressBefore(addr(11)));
		assertEquals(addr(11), model.getAddressBefore(addr(12)));
		assertEquals(addr(12), model.getAddressBefore(addr(13)));
		assertEquals(addr(13), model.getAddressBefore(addr(14)));
		assertEquals(addr(14), model.getAddressBefore(addr(15)));
		assertEquals(addr(15), model.getAddressBefore(addr(16)));
		assertEquals(addr(16), model.getAddressBefore(addr(17)));
		assertEquals(addr(17), model.getAddressBefore(addr(18)));
		assertEquals(addr(17), model.getAddressBefore(addr(19)));
	}

	@Test
	public void testGetPreviousAddressWithFunctionClosed() {
		model.setFunctionOpen(addr(0), false);

		assertNull(model.getAddressBefore(addr(0)));
		assertEquals(addr(0), model.getAddressBefore(addr(1)));
		assertEquals(addr(0), model.getAddressBefore(addr(2)));
		assertEquals(addr(0), model.getAddressBefore(addr(3)));
		assertEquals(addr(0), model.getAddressBefore(addr(4)));
		assertEquals(addr(4), model.getAddressBefore(addr(5)));
		assertEquals(addr(5), model.getAddressBefore(addr(6)));
		assertEquals(addr(6), model.getAddressBefore(addr(7)));
		assertEquals(addr(6), model.getAddressBefore(addr(8)));
		assertEquals(addr(6), model.getAddressBefore(addr(9)));
		assertEquals(addr(6), model.getAddressBefore(addr(10)));
		assertEquals(addr(10), model.getAddressBefore(addr(11)));
		assertEquals(addr(11), model.getAddressBefore(addr(12)));
		assertEquals(addr(12), model.getAddressBefore(addr(13)));
		assertEquals(addr(12), model.getAddressBefore(addr(14)));
		assertEquals(addr(12), model.getAddressBefore(addr(15)));
		assertEquals(addr(12), model.getAddressBefore(addr(16)));
		assertEquals(addr(16), model.getAddressBefore(addr(17)));
		assertEquals(addr(17), model.getAddressBefore(addr(18)));
		assertEquals(addr(17), model.getAddressBefore(addr(19)));
	}

}
