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
package agent.lldb.rmi;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import db.Transaction;
import generic.Unique;
import generic.test.category.NightlyCategory;
import ghidra.app.plugin.core.debug.utils.ManagedDomainObject;
import ghidra.dbg.util.PathPredicates;
import ghidra.debug.api.tracermi.TraceRmiAcceptor;
import ghidra.debug.api.tracermi.TraceRmiConnection;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.CodeUnit;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.*;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.listing.TraceCodeSpace;
import ghidra.trace.model.listing.TraceData;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.target.*;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.Msg;

@Category(NightlyCategory.class) // this may actually be an @PortSensitive test
public class LldbCommandsTest extends AbstractLldbTraceRmiTest {

	//@Test
	public void testManual() throws Exception {
		TraceRmiAcceptor acceptor = traceRmi.acceptOne(null);
		Msg.info(this,
			"Use: ghidra trace connect " + sockToStringForLldb(acceptor.getAddress()));
		TraceRmiConnection connection = acceptor.accept();
		Msg.info(this, "Connected: " + sockToStringForLldb(connection.getRemoteAddress()));
		connection.waitClosed();
		Msg.info(this, "Closed");
	}

	@Test
	public void testConnectErrorNoArg() throws Exception {
		String out = runThrowError("""
				script import ghidralldb
				ghidra trace connect
				quit
				""");
		assertThat(out, containsString("ghidra trace connect"));
		assertThat(out, containsString("error:"));
		assertThat(out, containsString("ADDRESS"));
	}

	@Test
	public void testConnect() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				quit
				""".formatted(PREAMBLE, addr));
	}

	@Test
	public void testDisconnect() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				ghidra trace disconnect
				quit
				""".formatted(PREAMBLE, addr));
	}

	@Test
	public void testStartTraceDefaults() throws Exception {
		// Default name and lcsp
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				ghidra trace start
				quit
				""".formatted(PREAMBLE, addr, getSpecimenPrint()));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/expPrint")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			assertEquals(PLAT.lang(),
				tb.trace.getBaseLanguage().getLanguageID().getIdAsString());
			assertEquals(PLAT.cSpec(),
				tb.trace.getBaseCompilerSpec().getCompilerSpecID().getIdAsString());
		}
	}

	@Test
	public void testStartTraceDefaultNoFile() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				ghidra trace start
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/noname")) {
			assertThat(mdo.get(), instanceOf(Trace.class));
		}
	}

	@Test
	public void testStartTraceCustomize() throws Exception {
		runThrowError(
			addr -> """
					%s
					ghidra trace connect %s
					file %s
					script ghidralldb.util.set_convenience_variable('ghidra-language','Toy:BE:64:default')
					script ghidralldb.util.set_convenience_variable('ghidra-compiler','default')
					ghidra trace start myToy
					quit
					"""
					.formatted(PREAMBLE, addr, getSpecimenPrint()));
		DomainFile dfMyToy = env.getProject().getProjectData().getFile("/New Traces/myToy");
		assertNotNull(dfMyToy);
		try (ManagedDomainObject mdo = new ManagedDomainObject(dfMyToy, false, false, monitor)) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			assertEquals("Toy:BE:64:default",
				tb.trace.getBaseLanguage().getLanguageID().getIdAsString());
			assertEquals("default",
				tb.trace.getBaseCompilerSpec().getCompilerSpecID().getIdAsString());
		}
	}

	@Test
	public void testStopTrace() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				ghidra trace start
				ghidra trace stop
				quit
				""".formatted(PREAMBLE, addr, getSpecimenPrint()));
		DomainFile df = env.getProject().getProjectData().getFile("/New Traces/lldb/expPrint");
		assertNotNull(df);
		// TODO: Given the 'quit' command, I'm not sure this assertion is checking anything.
		assertFalse(df.isOpen());
	}

	@Test
	public void testInfo() throws Exception {
		AtomicReference<String> refAddr = new AtomicReference<>();
		String out = runThrowError(addr -> {
			refAddr.set(addr);
			return """
					file %s
					%s
					script print("---Import---")
					ghidra trace info
					ghidra trace connect %s
					script print("---Connect---")
					ghidra trace info
					ghidra trace start
					script print("---Start---")
					ghidra trace info
					ghidra trace stop
					script print("---Stop---")
					ghidra trace info
					ghidra trace disconnect
					script print("---Disconnect---")
					ghidra trace info
					quit
					""".formatted(getSpecimenPrint(), PREAMBLE, addr);
		});

		assertEquals("""
				Not connected to Ghidra""",
			extractOutSection(out, "---Import---"));
		assertEquals("""
				Connected to Ghidra at %s
				No trace""".formatted(refAddr.get()),
			extractOutSection(out, "---Connect---"));
		assertEquals("""
				Connected to Ghidra at %s
				Trace active""".formatted(refAddr.get()),
			extractOutSection(out, "---Start---"));
		assertEquals("""
				Connected to Ghidra at %s
				No trace""".formatted(refAddr.get()),
			extractOutSection(out, "---Stop---"));
		assertEquals("""
				Not connected to Ghidra""",
			extractOutSection(out, "---Disconnect---"));
	}

	@Test
	public void testLcsp() throws Exception {
		String out = runThrowError(
			"""
					script import ghidralldb
					script print("---Import---")
					ghidra trace info-lcsp
					script print("---
					file %s
					script print("---File---")
					ghidra trace info-lcsp
					script ghidralldb.util.set_convenience_variable('ghidra-language','Toy:BE:64:default')
					script print("---Language---")
					ghidra trace info-lcsp
					script ghidralldb.util.set_convenience_variable('ghidra-compiler','posStack')
					script print("---Compiler---")
					ghidra trace info-lcsp
					quit
					"""
					.formatted(getSpecimenPrint()));

		assertEquals("""
				Selected Ghidra language: %s
				Selected Ghidra compiler: %s""".formatted(PLAT.lang(), PLAT.cSpec()),
			extractOutSection(out, "---File---"));
		assertEquals("""
				Selected Ghidra language: Toy:BE:64:default
				Selected Ghidra compiler: default""",
			extractOutSection(out, "---Language---"));
		assertEquals("""
				Selected Ghidra language: Toy:BE:64:default
				Selected Ghidra compiler: posStack""",
			extractOutSection(out, "---Compiler---"));
	}

	@Test
	public void testSave() throws Exception {
		traceManager.setSaveTracesByDefault(false);

		// For sanity check, verify failing to save drops data
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				ghidra trace start no-save
				ghidra trace tx-start "Create snapshot"
				ghidra trace new-snap "Scripted snapshot"
				ghidra trace tx-commit
				quit
				""".formatted(PREAMBLE, addr, getSpecimenPrint()));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/no-save")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			assertEquals(0, tb.trace.getTimeManager().getAllSnapshots().size());
		}

		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				ghidra trace start save
				ghidra trace tx-start "Create snapshot"
				ghidra trace new-snap "Scripted snapshot"
				ghidra trace tx-commit
				ghidra trace save
				quit
				""".formatted(PREAMBLE, addr, getSpecimenPrint()));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/save")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			assertEquals(1, tb.trace.getTimeManager().getAllSnapshots().size());
		}
	}

	@Test
	public void testSnapshot() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				ghidra trace start
				ghidra trace tx-start "Create snapshot"
				ghidra trace new-snap "Scripted snapshot"
				ghidra trace tx-commit
				quit
				""".formatted(PREAMBLE, addr, getSpecimenPrint()));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/expPrint")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceSnapshot snapshot = Unique.assertOne(tb.trace.getTimeManager().getAllSnapshots());
			assertEquals(0, snapshot.getKey());
			assertEquals("Scripted snapshot", snapshot.getDescription());
		}
	}

	@Test
	public void testPutmem() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				process launch --stop-at-entry
				ghidra trace start
				ghidra trace tx-start "Create snapshot"
				ghidra trace new-snap "Scripted snapshot"
				ghidra trace putmem `(void(*)())main` 10
				ghidra trace tx-commit
				script print("---Dump---")
				x/10bx `(void(*)())main`
				script print("---")
				kill
				quit
				""".formatted(PREAMBLE, addr, getSpecimenPrint()));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/expPrint")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = Unique.assertOne(tb.trace.getTimeManager().getAllSnapshots()).getKey();

			MemDump dump = parseHexDump(extractOutSection(out, "---Dump---"));
			ByteBuffer buf = ByteBuffer.allocate(dump.data().length);
			tb.trace.getMemoryManager().getBytes(snap, tb.addr(dump.address()), buf);

			assertArrayEquals(dump.data(), buf.array());
		}
	}

	// TODO: Test with ram from a second process (e.g., child)

	@Test
	public void testPutmemState() throws Exception {
		String out = runThrowError(addr -> """
				settings set interpreter.echo-commands false
				%s
				ghidra trace connect %s
				file %s
				process launch --stop-at-entry
				ghidra trace start
				ghidra trace tx-start "Create snapshot"
				ghidra trace new-snap "Scripted snapshot"
				ghidra trace putmem-state `(void(*)())main` 10 error
				ghidra trace tx-commit
				script print("---Start---")
				print/x (void(*)())main
				script print("---")
				kill
				quit
				""".formatted(PREAMBLE, addr, getSpecimenPrint()));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/expPrint")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = Unique.assertOne(tb.trace.getTimeManager().getAllSnapshots()).getKey();

			String eval = extractOutSection(out, "---Start---");
			Address addr = tb.addr(Stream.of(eval.split("\\s+"))
					.filter(s -> s.startsWith("0x"))
					.mapToLong(Long::decode)
					.findFirst()
					.orElseThrow());

			Entry<TraceAddressSnapRange, TraceMemoryState> entry =
				tb.trace.getMemoryManager().getMostRecentStateEntry(snap, addr);
			assertEquals(Map.entry(new ImmutableTraceAddressSnapRange(
				quantize(rng(addr, 10), 4096), Lifespan.at(0)), TraceMemoryState.ERROR), entry);
		}
	}

	@Test
	public void testDelmem() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				process launch --stop-at-entry
				ghidra trace start
				ghidra trace tx-start "Create snapshot"
				ghidra trace new-snap "Scripted snapshot"
				ghidra trace putmem `(void(*)())main` 10
				ghidra trace delmem `(void(*)())main` 5
				ghidra trace tx-commit
				script print("---Dump---")
				x/10bx (void(*)())main
				script print("---")
				kill
				quit
				""".formatted(PREAMBLE, addr, getSpecimenPrint()));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/expPrint")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = Unique.assertOne(tb.trace.getTimeManager().getAllSnapshots()).getKey();

			MemDump dump = parseHexDump(extractOutSection(out, "---Dump---"));
			Arrays.fill(dump.data(), 0, 5, (byte) 0);
			ByteBuffer buf = ByteBuffer.allocate(dump.data().length);
			tb.trace.getMemoryManager().getBytes(snap, tb.addr(dump.address()), buf);

			assertArrayEquals(dump.data(), buf.array());
		}
	}

	@Test
	public void testPutreg() throws Exception {
		// TODO: Test vector register, e.g., ymm0
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				process launch --stop-at-entry
				ghidra trace start
				expr $%s = 0xdeadbeef
				expr $%s = 1.5
				ghidra trace tx-start "Create snapshot"
				ghidra trace new-snap "Scripted snapshot"
				ghidra trace putreg
				ghidra trace tx-commit
				kill
				quit
				""".formatted(PREAMBLE, addr, getSpecimenPrint(), PLAT.intReg(), PLAT.floatReg()));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/expPrint")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = Unique.assertOne(tb.trace.getTimeManager().getAllSnapshots()).getKey();
			List<TraceObjectValue> regVals = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(0),
						PathPredicates.parse("Processes[].Threads[].Stack[].Registers"))
					.map(p -> p.getLastEntry())
					.toList();
			TraceObjectValue tobj = regVals.get(0);
			AddressSpace t1f0 = tb.trace.getBaseAddressFactory()
					.getAddressSpace(tobj.getCanonicalPath().toString());
			TraceMemorySpace regs = tb.trace.getMemoryManager().getMemorySpace(t1f0, false);

			RegisterValue intRegVal = regs.getValue(snap, tb.reg(PLAT.intReg()));
			assertEquals("deadbeef", intRegVal.getUnsignedValue().toString(16));

//			RegisterValue ymm0 = regs.getValue(snap, tb.reg("ymm0"));
//			// LLDB treats registers in arch's endian
//			assertEquals("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
//				ymm0.getUnsignedValue().toString(16));

			// It's either my version of lldb for Linux or just that x86 fp is weird.
			if (PLAT != PlatDep.X8664) {
				TraceData floatData;
				Register floatReg = Objects.requireNonNull(tb.reg(PLAT.floatReg()));
				DataType floatType = switch (floatReg.getMinimumByteSize()) {
					case 4 -> Float4DataType.dataType;
					case 8 -> Float8DataType.dataType;
					case 10 -> Float8DataType.dataType;
					default -> throw new AssertionError("Unknown float size");
				};
				try (Transaction tx = tb.trace.openTransaction("Float unit")) {
					TraceCodeSpace code = tb.trace.getCodeManager().getCodeSpace(t1f0, true);
					floatData = code.definedData().create(Lifespan.nowOn(0), floatReg, floatType);
				}
				assertEquals("1.5", floatData.getDefaultValueRepresentation());
			}
		}
	}

	@Test
	public void testDelreg() throws Exception {
		// TODO: Test vector register, e.g., ymm0
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				process launch --stop-at-entry
				ghidra trace start
				expr $%s = 0xdeadbeef
				expr $%s = 1.5
				ghidra trace tx-start "Create snapshot"
				ghidra trace new-snap "Scripted snapshot"
				ghidra trace putreg
				ghidra trace delreg
				ghidra trace tx-commit
				kill
				quit
				""".formatted(PREAMBLE, addr, getSpecimenPrint(), PLAT.intReg(), PLAT.floatReg()));
		// The spaces will be left over, but the values should be zeroed
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/expPrint")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = Unique.assertOne(tb.trace.getTimeManager().getAllSnapshots()).getKey();
			List<TraceObjectValue> regVals = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(0),
						PathPredicates.parse("Processes[].Threads[].Stack[].Registers"))
					.map(p -> p.getLastEntry())
					.toList();
			TraceObjectValue tobj = regVals.get(0);
			AddressSpace t1f0 = tb.trace.getBaseAddressFactory()
					.getAddressSpace(tobj.getCanonicalPath().toString());
			TraceMemorySpace regs = tb.trace.getMemoryManager().getMemorySpace(t1f0, false);

			RegisterValue intRegVal = regs.getValue(snap, tb.reg(PLAT.intReg()));
			assertEquals("0", intRegVal.getUnsignedValue().toString(16));

//			RegisterValue ymm0 = regs.getValue(snap, tb.reg("ymm0"));
//			assertEquals("0", ymm0.getUnsignedValue().toString(16));

			TraceData floatData;
			Register floatReg = Objects.requireNonNull(tb.reg(PLAT.floatReg()));
			DataType floatType = switch (floatReg.getMinimumByteSize()) {
				case 4 -> Float4DataType.dataType;
				case 8 -> Float8DataType.dataType;
				case 10 -> Float10DataType.dataType;
				default -> throw new AssertionError("Unknown float size");
			};
			try (Transaction tx = tb.trace.openTransaction("Float unit")) {
				TraceCodeSpace code = tb.trace.getCodeManager().getCodeSpace(t1f0, true);
				floatData = code.definedData().create(Lifespan.nowOn(0), floatReg, floatType);
			}
			assertEquals("0.0", floatData.getDefaultValueRepresentation());
		}
	}

	@Test
	public void testCreateObj() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra trace connect %s
				ghidra trace start
				ghidra trace tx-start "Create Object"
				script print("---Id---")
				ghidra trace create-obj Test.Objects[1]
				script print("---")
				ghidra trace tx-commit
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/noname")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Test.Objects[1]"));
			assertNotNull(object);
			String created = extractOutSection(out, "---Id---");
			long id = Long.parseLong(created.split("id=")[1].split(",")[0]);
			assertEquals(object.getKey(), id);
		}
	}

	@Test
	public void testInsertObj() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra trace connect %s
				ghidra trace start
				ghidra trace tx-start "Create Object"
				ghidra trace create-obj Test.Objects[1]
				script print("---Lifespan---")
				ghidra trace insert-obj Test.Objects[1]
				script print("---")
				ghidra trace tx-commit
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/noname")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Test.Objects[1]"));
			assertNotNull(object);
			Lifespan life = Unique.assertOne(object.getLife().spans());
			assertEquals(Lifespan.nowOn(0), life);
			String lifeStr = extractOutSection(out, "---Lifespan---");
			assertEquals("Inserted object: lifespan=[0,+inf)", lifeStr);
		}
	}

	@Test
	public void testRemoveObj() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				process launch --stop-at-entry
				ghidra trace start
				ghidra trace tx-start "Create Object"
				ghidra trace create-obj Test.Objects[1]
				ghidra trace insert-obj Test.Objects[1]
				ghidra trace set-snap 1
				ghidra trace remove-obj Test.Objects[1]
				ghidra trace tx-commit
				kill
				quit
				""".formatted(PREAMBLE, addr, getSpecimenPrint()));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/expPrint")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Test.Objects[1]"));
			assertNotNull(object);
			Lifespan life = Unique.assertOne(object.getLife().spans());
			assertEquals(Lifespan.at(0), life);
		}
	}

	@SuppressWarnings("unchecked")
	protected <T> T runTestSetValue(String extra, String lldbExpr, String gtype)
			throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				process launch --stop-at-entry
				ghidra trace start
				ghidra trace tx-start "Create Object"
				ghidra trace create-obj Test.Objects[1]
				ghidra trace insert-obj Test.Objects[1]
				%s
				ghidra trace set-value Test.Objects[1] test %s %s
				ghidra trace tx-commit
				kill
				quit
				""".formatted(PREAMBLE, addr, getSpecimenPrint(), extra, lldbExpr, gtype));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/expPrint")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Test.Objects[1]"));
			assertNotNull(object);
			TraceObjectValue value = object.getValue(0, "test");
			return value == null ? null : (T) value.getValue();
		}
	}

	// NB: Fails in gdb tests as well
	//@Test
	public void testSetValueNull() throws Exception {
		assertNull(runTestSetValue("", """
				(void)null\
				""", ""));
	}

	@Test
	public void testSetValueBool() throws Exception {
		assertEquals(Boolean.TRUE, runTestSetValue("", """
				(bool)1\
				""", ""));
	}

	@Test
	public void testSetValueByte() throws Exception {
		assertEquals(Byte.valueOf((byte) 1), runTestSetValue("", """
				(char)1\
				""", ""));
	}

	@Test
	public void testSetValueChar() throws Exception {
		assertEquals(Character.valueOf('A'), runTestSetValue("", """
				"'A'"\
				""", "CHAR"));
	}

	@Test
	public void testSetValueShort() throws Exception {
		assertEquals(Short.valueOf((short) 1), runTestSetValue("", """
				(short)1\
				""", ""));
	}

	@Test
	public void testSetValueInt() throws Exception {
		assertEquals(Integer.valueOf(1), runTestSetValue("", """
				(int)1\
				""", ""));
	}

	@Test
	public void testSetValueLong() throws Exception {
		assertEquals(Long.valueOf(1), runTestSetValue("", """
				(long)1\
				""", ""));
	}

	@Test
	@Ignore("LLDB Can't seem to allocate the string. EXC_BAD_ACCESS.")
	public void testSetValueString() throws Exception {
		assertEquals("\"Hello World!\"", runTestSetValue("", """
				'"Hello World!"'\
				""", ""));
	}

	@Test
	@Ignore("LLDB Can't seem to allocate the string. EXC_BAD_ACCESS.")
	public void testSetValueStringWide() throws Exception {
		assertEquals("L\"Hello World!\"", runTestSetValue("", """
				'L"Hello World!"'\
				""", ""));
	}

	@Test
	@Ignore("Temp var $x thing doesn't work")
	public void testSetValueBoolArr() throws Exception {
		assertArrayEquals(new boolean[] { true, false },
			runTestSetValue("expr bool $x[2]={ true, false }", "$x", ""));
	}

	@Test
	@Ignore("LLDB Can't seem to allocate the string. EXC_BAD_ACCESS.")
	public void testSetValueByteArrUsingString() throws Exception {
		// Because explicit array type is chosen, we get null terminator
		assertArrayEquals(new byte[] { 'H', 0, 'W', 0 }, runTestSetValue("", """
				'"H\\0W"'\
				""", "BYTE_ARR"));
	}

	@Test
	@Ignore("Temp var $x thing doesn't work")
	public void testSetValueByteArrUsingArray() throws Exception {
		assertArrayEquals(new byte[] { 'H', 0, 'W' },
			runTestSetValue("expr char $x[]={'H', 0, 'W'}", "$x", "BYTE_ARR"));
	}

	@Test
	@Ignore("LLDB Can't seem to allocate the string. EXC_BAD_ACCESS.")
	public void testSetValueCharArrUsingString() throws Exception {
		// Because explicit array type is chosen, we get null terminator
		assertArrayEquals(new char[] { 'H', 0, 'W', 0 }, runTestSetValue("", """
				'"H\\0W"'\
				""", "CHAR_ARR"));
	}

	@Test
	@Ignore("Temp var $x thing doesn't work")
	public void testSetValueCharArrUsingArray() throws Exception {
		assertArrayEquals(new char[] { 'H', 0, 'W' },
			runTestSetValue("expr char $x[]={'H', 0, 'W'}", "$x", "CHAR_ARR"));
	}

	@Test
	@Ignore("Temp var $x thing doesn't work")
	public void testSetValueShortArrUsingString() throws Exception {
		// Because explicit array type is chosen, we get null terminator
		assertArrayEquals(new short[] { 'H', 0, 'W', 0 },
			runTestSetValue("expr wchar_t $x[]=L\"H\\0W\"", "$x", "SHORT_ARR"));
	}

	@Test
	@Ignore("Temp var $x thing doesn't work")
	public void testSetValueShortArrUsingArray() throws Exception {
		assertArrayEquals(new short[] { 'H', 0, 'W' },
			runTestSetValue("expr short $x[]={'H', 0, 'W'}", "$x", "SHORT_ARR"));
	}

	@Test
	@Ignore("Temp var $x thing doesn't work")
	public void testSetValueIntArrayUsingMixedArray() throws Exception {
		// Because explicit array type is chosen, we get null terminator
		assertArrayEquals(new int[] { 'H', 0, 'W' },
			runTestSetValue("expr int $x[]={'H', 0, 'W'}", "$x", "INT_ARR"));
	}

	@Test
	@Ignore("Temp var $x thing doesn't work")
	public void testSetValueIntArrUsingArray() throws Exception {
		assertArrayEquals(new int[] { 1, 2, 3, 4 },
			runTestSetValue("expr int $x[]={1,2,3,4}", "$x", ""));
	}

	@Test
	@Ignore("Temp var $x thing doesn't work")
	public void testSetValueLongArr() throws Exception {
		assertArrayEquals(new long[] { 1, 2, 3, 4 },
			runTestSetValue("expr long long $x[]={1LL,2LL,3LL,4LL}", "$x", ""));
	}

	// Skip String[]. Trouble is expressing them in LLDB....

	@Test
	public void testSetValueAddress() throws Exception {
		Address address = runTestSetValue("", """
				(void*)0xdeadbeef\
				""", "");
		// Don't have the address factory to create expected address
		assertEquals(0xdeadbeefL, address.getOffset());
		assertEquals("ram", address.getAddressSpace().getName());
	}

	@Test
	public void testSetValueObject() throws Exception {
		TraceObject object = runTestSetValue("", "Test.Objects[1]", "OBJECT");
		assertEquals("Test.Objects[1]", object.getCanonicalPath().toString());
	}

	@Test
	public void testRetainValues() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				process launch --stop-at-entry
				ghidra trace start
				ghidra trace tx-start "Create Object"
				ghidra trace create-obj Test.Objects[1]
				ghidra trace insert-obj Test.Objects[1]
				ghidra trace set-value Test.Objects[1] [1] 10
				ghidra trace set-value Test.Objects[1] [2] 20
				ghidra trace set-value Test.Objects[1] [3] 30
				ghidra trace set-snap 10
				ghidra trace retain-values Test.Objects[1] [1] [3]
				ghidra trace tx-commit
				kill
				quit
				""".formatted(PREAMBLE, addr, getSpecimenPrint()));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/expPrint")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Test.Objects[1]"));
			assertNotNull(object);
			assertEquals(Map.ofEntries(
				Map.entry("[1]", Lifespan.nowOn(0)),
				Map.entry("[2]", Lifespan.span(0, 9)),
				Map.entry("[3]", Lifespan.nowOn(0))),
				object.getValues(Lifespan.ALL)
						.stream()
						.collect(Collectors.toMap(v -> v.getEntryKey(), v -> v.getLifespan())));
		}
	}

	@Test
	public void testGetObj() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra trace connect %s
				ghidra trace start
				ghidra trace tx-start "Create Object"
				script print("---Id---")
				ghidra trace create-obj Test.Objects[1]
				script print("---")
				ghidra trace tx-commit
				script print("---GetObject---")
				ghidra trace get-obj Test.Objects[1]
				script print("---")
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/noname")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Test.Objects[1]"));
			assertNotNull(object);
			String getObject = extractOutSection(out, "---GetObject---");
			assertEquals("%d\tTest.Objects[1]".formatted(object.getKey()), getObject);
		}
	}

	@Test
	public void testGetValues() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				process launch --stop-at-entry
				ghidra trace start
				ghidra trace tx-start "Create Object"
				ghidra trace create-obj Test.Objects[1]
				ghidra trace insert-obj Test.Objects[1]
				ghidra trace set-value Test.Objects[1] vbool true
				ghidra trace set-value Test.Objects[1] vbyte (char)1
				ghidra trace set-value Test.Objects[1] vchar "'A'" CHAR
				ghidra trace set-value Test.Objects[1] vshort (short)2
				ghidra trace set-value Test.Objects[1] vint 3
				ghidra trace set-value Test.Objects[1] vlong 4LL
				ghidra trace set-value Test.Objects[1] vaddr (void*)0xdeadbeef
				ghidra trace set-value Test.Objects[1] vobj Test.Objects[1] OBJECT
				ghidra trace tx-commit
				script print("---GetValues---")
				ghidra trace get-values Test.Objects[1].
				script print("---")
				kill
				quit
				""".formatted(PREAMBLE, addr, getSpecimenPrint()));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/expPrint")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			assertEquals(
				"""
						Parent          Key    Span     Value           Type
						Test.Objects[1] vaddr  [0,+inf) ram:deadbeef    ADDRESS
						Test.Objects[1] vbool  [0,+inf) True            BOOL
						Test.Objects[1] vbyte  [0,+inf) 1               BYTE
						Test.Objects[1] vchar  [0,+inf) 'A'             CHAR
						Test.Objects[1] vint   [0,+inf) 3               INT
						Test.Objects[1] vlong  [0,+inf) 4               LONG
						Test.Objects[1] vobj   [0,+inf) Test.Objects[1] OBJECT
						Test.Objects[1] vshort [0,+inf) 2               SHORT\
						""",
				extractOutSection(out, "---GetValues---"));
		}
	}

	@Test
	public void testGetValuesRng() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				process launch --stop-at-entry
				ghidra trace start
				ghidra trace tx-start "Create Object"
				ghidra trace create-obj Test.Objects[1]
				ghidra trace insert-obj Test.Objects[1]
				ghidra trace set-value Test.Objects[1] vaddr (void*)0xdeadbeef
				ghidra trace tx-commit
				script print("---GetValues---")
				ghidra trace get-values-rng (void*)0xdeadbeef 10
				script print("---")
				kill
				quit
				""".formatted(PREAMBLE, addr, getSpecimenPrint()));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/expPrint")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			assertEquals("""
					Parent          Key   Span     Value        Type
					Test.Objects[1] vaddr [0,+inf) ram:deadbeef ADDRESS\
					""",
				extractOutSection(out, "---GetValues---"));
		}
	}

	//@Test
	public void testActivateObject() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				process launch --stop-at-entry
				ghidra trace start
				ghidra trace tx-start "Create Object"
				ghidra trace create-obj Test.Objects[1]
				ghidra trace insert-obj Test.Objects[1]
				ghidra trace tx-commit
				ghidra trace activate Test.Objects[1]
				kill
				quit
				""".formatted(PREAMBLE, addr, getSpecimenPrint()));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/expPrint")) {
			assertSame(mdo.get(), traceManager.getCurrentTrace());
			assertEquals("Test.Objects[1]",
				traceManager.getCurrentObject().getCanonicalPath().toString());
		}
	}

	@Test
	public void testDisassemble() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				process launch --stop-at-entry
				ghidra trace start
				ghidra trace tx-start "Tx"
				ghidra trace putmem `(void(*)())main` 10
				script print("---Disassemble---")
				ghidra trace disassemble `(void(*)())main`
				script print("---")
				ghidra trace tx-commit
				kill
				quit
				""".formatted(PREAMBLE, addr, getSpecimenPrint()));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/expPrint")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Not concerned about specifics, so long as disassembly occurs
			long total = 0;
			for (CodeUnit cu : tb.trace.getCodeManager().definedUnits().get(0, true)) {
				total += cu.getLength();
			}
			assertEquals("Disassembled %d bytes".formatted(total),
				extractOutSection(out, "---Disassemble---"));
		}
	}

	@Test
	public void testPutProcesses() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				ghidra trace start
				ghidra trace tx-start "Tx"
				ghidra trace put-processes
				ghidra trace tx-commit
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/noname")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Would be nice to control / validate the specifics
			Collection<TraceObject> processes = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(0), PathPredicates.parse("Processes[]"))
					.map(p -> p.getDestination(null))
					.toList();
			assertEquals(1, processes.size());
		}
	}

	@Test
	public void testPutAvailable() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				ghidra trace start
				ghidra trace tx-start "Tx"
				ghidra trace put-available
				ghidra trace tx-commit
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/noname")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Would be nice to control / validate the specifics
			Collection<TraceObject> available = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(0), PathPredicates.parse("Available[]"))
					.map(p -> p.getDestination(null))
					.toList();
			assertThat(available.size(), greaterThan(2));
		}
	}

	@Test
	public void testPutBreakpoints() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				process launch --stop-at-entry
				ghidra trace start
				ghidra trace tx-start "Tx"
				breakpoint set --name main
				breakpoint set -H --name main
				ghidra trace put-breakpoints
				ghidra trace tx-commit
				kill
				quit
				""".formatted(PREAMBLE, addr, getSpecimenPrint()));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/expPrint")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			List<TraceObjectValue> procBreakLocVals = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(0),
						PathPredicates.parse("Processes[].Breakpoints[]"))
					.map(p -> p.getLastEntry())
					.sorted(Comparator.comparing(TraceObjectValue::getEntryKey))
					.toList();
			assertEquals(2, procBreakLocVals.size());
			AddressRange rangeMain =
				procBreakLocVals.get(0).getChild().getValue(0, "_range").castValue();
			Address main = rangeMain.getMinAddress();

			assertBreakLoc(procBreakLocVals.get(0), "[1.1]", main, 1,
				Set.of(TraceBreakpointKind.SW_EXECUTE),
				"main");
			assertBreakLoc(procBreakLocVals.get(1), "[2.1]", main, 1,
				Set.of(TraceBreakpointKind.HW_EXECUTE),
				"main");
		}
	}

	@Test
	public void testPutWatchpoints() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				process launch --stop-at-entry
				ghidra trace start
				ghidra trace tx-start "Tx"
				watchpoint set expression -s 1 -- `(void(*)())main`
				watchpoint set expression -s 1 -w read -- `(void(*)())main`+-0x20
				watchpoint set expression -s 1 -w read_write -- `(void(*)())main`+0x30
				ghidra trace put-watchpoints
				ghidra trace tx-commit
				kill
				quit
				""".formatted(PREAMBLE, addr, getSpecimenPrint()));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/expPrint")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			List<TraceObjectValue> procWatchLocVals = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(0),
						PathPredicates.parse("Processes[].Watchpoints[]"))
					.map(p -> p.getLastEntry())
					.sorted(Comparator.comparing(TraceObjectValue::getEntryKey))
					.toList();
			assertEquals(3, procWatchLocVals.size());
			AddressRange rangeMain0 =
				procWatchLocVals.get(0).getChild().getValue(0, "_range").castValue();
			Address main0 = rangeMain0.getMinAddress();
			AddressRange rangeMain1 =
				procWatchLocVals.get(1).getChild().getValue(0, "_range").castValue();
			Address main1 = rangeMain1.getMinAddress();
			AddressRange rangeMain2 =
				procWatchLocVals.get(2).getChild().getValue(0, "_range").castValue();
			Address main2 = rangeMain2.getMinAddress();

			assertWatchLoc(procWatchLocVals.get(0), "[1]", main0, (int) rangeMain0.getLength(),
				Set.of(TraceBreakpointKind.WRITE), "main");
			assertWatchLoc(procWatchLocVals.get(1), "[2]", main1, (int) rangeMain1.getLength(),
				Set.of(TraceBreakpointKind.READ), "main");
			assertWatchLoc(procWatchLocVals.get(2), "[3]", main2, (int) rangeMain2.getLength(),
				Set.of(TraceBreakpointKind.READ, TraceBreakpointKind.WRITE), "main");
		}
	}

	@Test
	public void testPutEnvironment() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				process launch --stop-at-entry
				ghidra trace start
				ghidra trace tx-start "Tx"
				ghidra trace put-environment
				ghidra trace tx-commit
				kill
				quit
				""".formatted(PREAMBLE, addr, getSpecimenPrint()));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/expPrint")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Assumes LLDB on Linux amd64
			TraceObject env =
				Objects.requireNonNull(tb.objAny("Processes[].Environment", Lifespan.at(0)));
			assertEquals("lldb", env.getValue(0, "_debugger").getValue());
			assertEquals(PLAT.name(), env.getValue(0, "_arch").getValue());
			assertLocalOs(env.getValue(0, "_os").castValue());
			assertEquals(PLAT.endian(), env.getValue(0, "_endian").getValue());
		}
	}

	@Test
	public void testPutRegions() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				process launch --stop-at-entry
				ghidra trace start
				ghidra trace tx-start "Tx"
				ghidra trace put-regions
				ghidra trace tx-commit
				kill
				quit
				""".formatted(PREAMBLE, addr, getSpecimenPrint()));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/expPrint")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Would be nice to control / validate the specifics
			Collection<? extends TraceMemoryRegion> all =
				tb.trace.getMemoryManager().getAllRegions();
			assertThat(all.size(), greaterThan(2));
		}
	}

	@Test
	public void testPutModules() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				process launch --stop-at-entry
				ghidra trace start
				ghidra trace tx-start "Tx"
				ghidra trace put-modules
				ghidra trace tx-commit
				kill
				quit
				""".formatted(PREAMBLE, addr, getSpecimenPrint()));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/expPrint")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Would be nice to control / validate the specifics
			Collection<? extends TraceModule> all = tb.trace.getModuleManager().getAllModules();
			TraceModule modExpPrint =
				Unique.assertOne(all.stream().filter(m -> m.getName().contains("expPrint")));
			assertNotEquals(tb.addr(0), Objects.requireNonNull(modExpPrint.getBase()));
		}
	}

	@Test
	public void testPutThreads() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				process launch --stop-at-entry
				ghidra trace start
				ghidra trace tx-start "Tx"
				ghidra trace put-threads
				ghidra trace tx-commit
				kill
				quit
				""".formatted(PREAMBLE, addr, getSpecimenPrint()));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/expPrint")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Would be nice to control / validate the specifics
			Unique.assertOne(tb.trace.getThreadManager().getAllThreads());
		}
	}

	@Test
	public void testPutFrames() throws Exception {
		// Cheat a little by switching to synchronous mode
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				process launch --stop-at-entry
				breakpoint set -n puts
				script lldb.debugger.SetAsync(False)
				continue
				script lldb.debugger.SetAsync(True)
				ghidra trace start
				ghidra trace tx-start "Tx"
				ghidra trace put-frames
				ghidra trace tx-commit
				kill
				quit
				""".formatted(PREAMBLE, addr, getSpecimenPrint()));

		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/expPrint")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Would be nice to control / validate the specifics
			List<TraceObject> stack = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(0),
						PathPredicates.parse("Processes[].Threads[].Stack[]"))
					.map(p -> p.getDestination(null))
					.toList();
			assertThat(stack.size(), greaterThan(2));
		}
	}

	@Test
	public void testMinimal() throws Exception {
		Function<String, String> scriptSupplier = addr -> """
				%s
				ghidra trace connect %s
				""".formatted(PREAMBLE, addr);
		try (LldbAndConnection conn = startAndConnectLldb(scriptSupplier)) {
			conn.execute("script print('FINISHED')");
		}
	}
}
