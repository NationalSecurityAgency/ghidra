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
package ghidra.app.plugin.core.debug.gui.register;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.Before;
import org.junit.experimental.categories.Category;

import db.Transaction;
import generic.test.category.NightlyCategory;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerIntegrationTest;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingProvider;
import ghidra.app.plugin.core.debug.service.control.DebuggerControlServicePlugin;
import ghidra.app.services.DebuggerControlService;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.guest.TraceGuestPlatform;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.listing.TraceCodeSpace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.exception.DuplicateNameException;

@Category(NightlyCategory.class) // this may actually be an @PortSensitive test
public abstract class AbstractDebuggerRegistersProviderTest
		extends AbstractGhidraHeadedDebuggerIntegrationTest {

	protected TraceGuestPlatform toy;

	protected DebuggerRegistersPlugin registersPlugin;
	protected DebuggerRegistersProvider registersProvider;
	protected DebuggerListingPlugin listingPlugin;
	protected DebuggerControlService controlService;

	protected Register r0;
	protected Register pc;
	protected Register sp;
	protected Register contextreg;

	protected Register r0h;
	protected Register r0l;
	protected Register pch;
	protected Register pcl;

	protected Set<Register> baseRegs;

	protected StructureDataType r0Struct;

	@Before
	public void setUpRegistersProviderTest() throws Exception {
		registersPlugin = addPlugin(tool, DebuggerRegistersPlugin.class);
		registersProvider = waitForComponentProvider(DebuggerRegistersProvider.class);
		listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);
		controlService = addPlugin(tool, DebuggerControlServicePlugin.class);

		// TODO: Workaround issue in testing framework.
		waitForComponentProvider(DebuggerListingProvider.class).setAutoDisassemble(false);

		createTrace();
		r0 = tb.language.getRegister("r0");
		pc = tb.language.getProgramCounter();
		sp = tb.language.getDefaultCompilerSpec().getStackPointer();
		contextreg = tb.language.getContextBaseRegister();

		pch = tb.language.getRegister("pch");
		pcl = tb.language.getRegister("pcl");

		r0h = tb.language.getRegister("r0h");
		r0l = tb.language.getRegister("r0l");

		r0Struct = new StructureDataType("r0_struct", 0);
		r0Struct.add(SignedDWordDataType.dataType, "hi", "");
		r0Struct.add(DWordDataType.dataType, "lo", "");

		baseRegs = tb.language.getRegisters()
				.stream()
				.filter(Register::isBaseRegister)
				.collect(Collectors.toSet());
	}

	protected void setUpGuestRegistersProviderTest() throws Exception {
		registersPlugin = addPlugin(tool, DebuggerRegistersPlugin.class);
		registersProvider = waitForComponentProvider(DebuggerRegistersProvider.class);
		listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);
		controlService = addPlugin(tool, DebuggerControlServicePlugin.class);

		createTrace();
		createToyPlatform();

		r0 = tb.reg(toy, "r0");
		pc = toy.getLanguage().getProgramCounter();
		sp = toy.getCompilerSpec().getStackPointer();
		contextreg = toy.getLanguage().getContextBaseRegister();

		pch = tb.reg(toy, "pch");
		pcl = tb.reg(toy, "pcl");

		r0h = tb.reg(toy, "r0h");
		r0l = tb.reg(toy, "r0l");

		r0Struct = new StructureDataType("r0_struct", 0);
		r0Struct.add(SignedDWordDataType.dataType, "hi", "");
		r0Struct.add(DWordDataType.dataType, "lo", "");

		baseRegs = toy.getLanguage()
				.getRegisters()
				.stream()
				.filter(Register::isBaseRegister)
				.collect(Collectors.toSet());
	}

	protected TraceThread addThread() throws DuplicateNameException {
		return addThread("Thread1");
	}

	protected TraceThread addThread(String threadName) throws DuplicateNameException {
		try (Transaction tx = tb.startTransaction()) {
			return tb.trace.getThreadManager().createThread(threadName, 0);
		}
	}

	public void createToyPlatform() throws Exception {
		try (Transaction tx = tb.startTransaction()) {
			toy = tb.trace.getPlatformManager()
					.addGuestPlatform(getToyBE64Language().getDefaultCompilerSpec());
			toy.addMappedRange(tb.addr(0), tb.addr(toy, 0), -1);
			toy.addMappedRegisterRange();
		}
	}

	protected TracePlatform getPlatform() {
		return tb.host;
	}

	protected void activateThread(TraceThread thread) {
		traceManager.activateThread(thread);
	}

	protected void addRegisterValues(TraceThread thread) {
		try (Transaction tx = tb.startTransaction()) {
			addRegisterValues(thread, tx);
		}
	}

	protected void addRegisterValues(TraceThread thread, Transaction tx) {
		TraceMemorySpace regVals =
			tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
		regVals.putBytes(0, pc, tb.buf(0, 0, 0, 0, 0, 0x40, 0, 0));
		regVals.putBytes(0, sp, tb.buf(0x1f, 0, 0, 0, 0, 0, 0, 0));
		regVals.putBytes(0, r0, tb.buf(1, 2, 3, 4, 5, 6, 7, 8));
	}

	protected void addRegisterTypes(TraceThread thread, Transaction tx)
			throws CodeUnitInsertionException {
		TraceCodeSpace regCode =
			tb.trace.getCodeManager().getCodeRegisterSpace(thread, true);
		DataTypeManager dtm = tb.trace.getDataTypeManager();
		AddressSpace space = tb.host.getAddressFactory().getDefaultAddressSpace();
		PointerTypedef ramPtr = new PointerTypedef(null, VoidDataType.dataType, -1, dtm, space);
		regCode.definedData().create(getPlatform(), Lifespan.nowOn(0), pc, ramPtr);
		regCode.definedData().create(getPlatform(), Lifespan.nowOn(0), r0, r0Struct);
	}

	protected void addRegisterTypes(TraceThread thread) throws CodeUnitInsertionException {
		try (Transaction tx = tb.startTransaction()) {
			addRegisterTypes(thread, tx);
		}
	}

	protected RegisterRow findRegisterRow(Register reg) {
		RegisterRow row = getRegisterRow(reg);
		if (row == null) {
			throw new NoSuchElementException(reg.getName());
		}
		return row;
	}

	protected RegisterRow getRegisterRow(Register reg) {
		return registersProvider.regMap.get(reg);
	}

	protected void setRowText(RegisterRow row, String text) {
		assertTrue(row.isValueEditable());
		row.setValue(new BigInteger(text, 16));
	}

	protected void setRowRepr(RegisterRow row, String repr) {
		assertTrue(row.isRepresentationEditable());
		row.setRepresentation(repr);
	}

	protected void assertRowValueEmpty(RegisterRow row) {
		assertEquals(BigInteger.ZERO, row.getValue());
	}

	protected void assertRowTypeEmpty(RegisterRow row) {
		assertNull(row.getDataType());
	}

	protected void assertPCRowValueEmpty() {
		assertRowValueEmpty(findRegisterRow(pc));
	}

	protected void assertPCRowTypeEmpty() {
		assertRowTypeEmpty(findRegisterRow(pc));
	}

	protected void assertR0RowValueEmpty() {
		assertRowValueEmpty(findRegisterRow(r0));
	}

	protected void assertR0RowTypeEmpty() {
		assertRowTypeEmpty(findRegisterRow(r0));
	}

	protected void assertPCRowValuePopulated() {
		RegisterRow row = findRegisterRow(pc);
		assertEquals(0x00400000, row.getValue().longValue());

		RegisterRow rowH = findRegisterRow(pch);
		assertEquals(0x00000000, rowH.getValue().longValue());

		RegisterRow rowL = findRegisterRow(pcl);
		assertEquals(0x00400000, rowL.getValue().longValue());
	}

	protected void assertPCRowTypePopulated() {
		RegisterRow row = findRegisterRow(pc);
		assertTypeEquals(PointerDataType.dataType, row.getDataType());

		//assertTrue(row.data.getValue() instanceof Address);
		//Address pcAddr = (Address) row.data.getValue();
		//assertEquals("ram", pcAddr.getAddressSpace().getName());
		//assertEquals(0x00400000, pcAddr.getOffset());
		//assertEquals("<INVALID>", row.reprField.getText()); // No memory layout is provided

		RegisterRow rowH = findRegisterRow(pch);
		assertNull(rowH.getDataType());

		RegisterRow rowL = findRegisterRow(pcl);
		assertNull(rowL.getDataType());
	}

	protected void assertR0RowValuePopulated() {
		RegisterRow row = findRegisterRow(r0);
		assertEquals(0x0102030405060708L, row.getValue().longValue());

		RegisterRow rowL = findRegisterRow(r0l);
		assertEquals(0x05060708, rowL.getValue().longValue());

		RegisterRow rowH = findRegisterRow(r0h);
		assertEquals(0x01020304, rowH.getValue().longValue());
	}

	protected void assertR0RowTypePopulated() {
		RegisterRow row = findRegisterRow(r0);
		assertTypeEquals(r0Struct, row.getDataType());

		RegisterRow rowL = findRegisterRow(r0l);
		assertTypeEquals(DWordDataType.dataType, rowL.getDataType());

		RegisterRow rowH = findRegisterRow(r0h);
		assertTypeEquals(SignedDWordDataType.dataType, rowH.getDataType());
	}

	long encodeDouble(double value) {
		ByteBuffer buf = ByteBuffer.allocate(Double.BYTES);
		buf.putDouble(0, value);
		return buf.getLong(0);
	}
}
