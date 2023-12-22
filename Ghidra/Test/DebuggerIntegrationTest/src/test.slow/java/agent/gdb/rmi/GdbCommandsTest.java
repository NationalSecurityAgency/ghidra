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
package agent.gdb.rmi;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.junit.Test;
import org.junit.experimental.categories.Category;

import db.Transaction;
import generic.Unique;
import generic.test.category.NightlyCategory;
import ghidra.app.plugin.core.debug.utils.ManagedDomainObject;
import ghidra.dbg.testutil.DummyProc;
import ghidra.dbg.util.PathPredicates;
import ghidra.debug.api.tracermi.TraceRmiAcceptor;
import ghidra.debug.api.tracermi.TraceRmiConnection;
import ghidra.framework.Application;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.*;
import ghidra.program.model.data.Float10DataType;
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
public class GdbCommandsTest extends AbstractGdbTraceRmiTest {

	//@Test
	public void testManual() throws Exception {
		TraceRmiAcceptor acceptor = traceRmi.acceptOne(null);
		Msg.info(this,
			"Use: ghidra trace connect " + sockToStringForGdb(acceptor.getAddress()));
		TraceRmiConnection connection = acceptor.accept();
		Msg.info(this, "Connected: " + sockToStringForGdb(connection.getRemoteAddress()));
		connection.waitClosed();
		Msg.info(this, "Closed");
	}

	@Test
	public void testConnectErrorNoArg() throws Exception {
		try {
			runThrowError("""
					%s
					ghidra trace connect
					quit
					""".formatted(PREAMBLE));
			fail();
		}
		catch (GdbError e) {
			assertThat(e.stderr, containsString("'ghidra trace connect'"));
			assertThat(e.stderr, containsString("'address'"));
		}
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
				file bash
				ghidra trace start
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			assertEquals("x86:LE:64:default",
				tb.trace.getBaseLanguage().getLanguageID().getIdAsString());
			assertEquals("gcc",
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
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/noname")) {
			assertThat(mdo.get(), instanceOf(Trace.class));
		}
	}

	@Test
	public void testStartTraceCustomize() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file bash
				set ghidra-language Toy:BE:64:default
				set ghidra-compiler default
				ghidra trace start myToy
				quit
				""".formatted(PREAMBLE, addr));
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
		// TODO: This test assumes gdb and the target file bash are x86-64
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file bash
				ghidra trace start
				ghidra trace stop
				quit
				""".formatted(PREAMBLE, addr));
		DomainFile dfBash = env.getProject().getProjectData().getFile("/New Traces/gdb/bash");
		assertNotNull(dfBash);
		// TODO: Given the 'quit' command, I'm not sure this assertion is checking anything.
		assertFalse(dfBash.isOpen());
	}

	@Test
	public void testInfo() throws Exception {
		AtomicReference<String> refAddr = new AtomicReference<>();
		String out = runThrowError(addr -> {
			refAddr.set(addr);
			return """
					%s
					file bash
					echo \\n---Import---\\n
					ghidra trace info
					echo \\n---BeforeConnect---\\n
					ghidra trace connect %s
					echo \\n---Connect---\\n
					ghidra trace info
					ghidra trace start
					echo \\n---Start---\\n
					ghidra trace info
					ghidra trace stop
					echo \\n---Stop---\\n
					ghidra trace info
					ghidra trace disconnect
					echo \\n---Disconnect---\\n
					ghidra trace info
					quit
					""".formatted(PREAMBLE, addr);
		});

		assertEquals("""
				Not connected to Ghidra""",
			extractOutSection(out, "---Import---"));
		assertEquals("""
				Connected to %s %s at %s
				No trace""".formatted(
			Application.getName(), Application.getApplicationVersion(), refAddr.get()),
			extractOutSection(out, "---Connect---"));
		assertEquals("""
				Connected to %s %s at %s
				Trace active""".formatted(
			Application.getName(), Application.getApplicationVersion(), refAddr.get()),
			extractOutSection(out, "---Start---"));
		assertEquals("""
				Connected to %s %s at %s
				No trace""".formatted(
			Application.getName(), Application.getApplicationVersion(), refAddr.get()),
			extractOutSection(out, "---Stop---"));
		assertEquals("""
				Not connected to Ghidra""",
			extractOutSection(out, "---Disconnect---"));
	}

	@Test
	public void testLcsp() throws Exception {
		// TODO: This test assumes x86-64 on test system
		String out = runThrowError("""
				%s
				echo \\n---Import---\\n
				ghidra trace lcsp
				echo \\n---\\n
				file bash
				echo \\n---File---\\n
				ghidra trace lcsp
				set ghidra-language Toy:BE:64:default
				echo \\n---Language---\\n
				ghidra trace lcsp
				set ghidra-compiler posStack
				echo \\n---Compiler---\\n
				ghidra trace lcsp
				quit
				""".formatted(PREAMBLE));
		assertEquals("""
				Selected Ghidra language: DATA:LE:64:default
				Selected Ghidra compiler: pointer64""",
			extractOutSection(out, "---Import---"));
		assertEquals("""
				Selected Ghidra language: x86:LE:64:default
				Selected Ghidra compiler: gcc""",
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
				file bash
				ghidra trace start no-save
				ghidra trace tx-start "Create snapshot"
				ghidra trace new-snap "Scripted snapshot"
				ghidra trace tx-commit
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/no-save")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			assertEquals(0, tb.trace.getTimeManager().getAllSnapshots().size());
		}

		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file bash
				ghidra trace start save
				ghidra trace tx-start "Create snapshot"
				ghidra trace new-snap "Scripted snapshot"
				ghidra trace tx-commit
				ghidra trace save
				quit
				""".formatted(PREAMBLE, addr));
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
				file bash
				ghidra trace start
				ghidra trace tx-start "Create snapshot"
				ghidra trace new-snap "Scripted snapshot"
				ghidra trace tx-commit
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
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
				file bash
				start
				ghidra trace start
				ghidra trace tx-start "Create snapshot"
				ghidra trace new-snap "Scripted snapshot"
				ghidra trace putmem &main 10
				ghidra trace tx-commit
				echo \\n---Dump---\\n
				x/10bx main
				echo \\n---
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = Unique.assertOne(tb.trace.getTimeManager().getAllSnapshots()).getKey();

			MemDump dump = parseHexDump(extractOutSection(out, "---Dump---"));
			ByteBuffer buf = ByteBuffer.allocate(dump.data().length);
			tb.trace.getMemoryManager().getBytes(snap, tb.addr(dump.address()), buf);

			assertArrayEquals(dump.data(), buf.array());
		}
	}

	@Test
	public void testPutmemInferior2() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra trace connect %s
				add-inferior
				inferior 2
				file bash
				start
				ghidra trace start
				ghidra trace tx-start "Create snapshot"
				ghidra trace new-snap "Scripted snapshot"
				ghidra trace putmem &main 10
				ghidra trace tx-commit
				echo \\n---Dump---\\n
				x/10bx main
				echo \\n---
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			AddressSpace ram2 = tb.trace.getBaseAddressFactory().getAddressSpace("ram2");
			assertNotNull(ram2);
			long snap = Unique.assertOne(tb.trace.getTimeManager().getAllSnapshots()).getKey();

			MemDump dump = parseHexDump(extractOutSection(out, "---Dump---"));
			ByteBuffer buf = ByteBuffer.allocate(dump.data().length);
			tb.trace.getMemoryManager().getBytes(snap, ram2.getAddress(dump.address()), buf);

			assertArrayEquals(dump.data(), buf.array());
		}
	}

	@Test
	public void testPutmemState() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file bash
				start
				ghidra trace start
				ghidra trace tx-start "Create snapshot"
				ghidra trace new-snap "Scripted snapshot"
				ghidra trace putmem-state &main 10 error
				ghidra trace tx-commit
				echo \\n---Start---\\n
				print/x &main
				echo \\n---
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = Unique.assertOne(tb.trace.getTimeManager().getAllSnapshots()).getKey();

			String eval = extractOutSection(out, "---Start---");
			Address addr = tb.addr(Long.decode(eval.split("=")[1].trim()));

			Entry<TraceAddressSnapRange, TraceMemoryState> entry =
				tb.trace.getMemoryManager().getMostRecentStateEntry(snap, addr);
			assertEquals(Map.entry(new ImmutableTraceAddressSnapRange(
				new AddressRangeImpl(addr, 10), Lifespan.at(0)), TraceMemoryState.ERROR), entry);
		}
	}

	@Test
	public void testDelmem() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file bash
				start
				ghidra trace start
				ghidra trace tx-start "Create snapshot"
				ghidra trace new-snap "Scripted snapshot"
				ghidra trace putmem &main 10
				ghidra trace delmem &main 5
				ghidra trace tx-commit
				echo \\n---Dump---\\n
				x/10bx main
				echo \\n---
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
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
		String count = IntStream.iterate(0, i -> i < 32, i -> i + 1)
				.mapToObj(Integer::toString)
				.collect(Collectors.joining(",", "{", "}"));
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file bash
				start
				ghidra trace start
				set $ymm0.v32_int8 = %s
				set $st0 = 1.5
				ghidra trace tx-start "Create snapshot"
				ghidra trace new-snap "Scripted snapshot"
				ghidra trace putreg
				ghidra trace tx-commit
				kill
				quit
				""".formatted(PREAMBLE, addr, count));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = Unique.assertOne(tb.trace.getTimeManager().getAllSnapshots()).getKey();
			AddressSpace t1f0 = tb.trace.getBaseAddressFactory()
					.getAddressSpace("Inferiors[1].Threads[1].Stack[0].Registers");
			TraceMemorySpace regs = tb.trace.getMemoryManager().getMemorySpace(t1f0, false);
			RegisterValue ymm0 = regs.getValue(snap, tb.reg("ymm0"));
			// GDB treats registers in arch's endian
			assertEquals("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
				ymm0.getUnsignedValue().toString(16));

			TraceData st0;
			try (Transaction tx = tb.trace.openTransaction("Float80 unit")) {
				TraceCodeSpace code = tb.trace.getCodeManager().getCodeSpace(t1f0, true);
				st0 = code.definedData()
						.create(Lifespan.nowOn(0), tb.reg("st0"), Float10DataType.dataType);
			}

			assertEquals("1.5", st0.getDefaultValueRepresentation());
		}
	}

	@Test
	public void testDelreg() throws Exception {
		String count = IntStream.iterate(0, i -> i < 32, i -> i + 1)
				.mapToObj(Integer::toString)
				.collect(Collectors.joining(",", "{", "}"));
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file bash
				start
				ghidra trace start
				set $ymm0.v32_int8 = %s
				set $st0 = 1.5
				ghidra trace tx-start "Create snapshot"
				ghidra trace new-snap "Scripted snapshot"
				ghidra trace putreg
				ghidra trace delreg
				ghidra trace tx-commit
				kill
				quit
				""".formatted(PREAMBLE, addr, count));
		// The spaces will be left over, but the values should be zeroed
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = Unique.assertOne(tb.trace.getTimeManager().getAllSnapshots()).getKey();
			AddressSpace t1f0 = tb.trace.getBaseAddressFactory()
					.getAddressSpace("Inferiors[1].Threads[1].Stack[0].Registers");
			TraceMemorySpace regs = tb.trace.getMemoryManager().getMemorySpace(t1f0, false);
			RegisterValue ymm0 = regs.getValue(snap, tb.reg("ymm0"));
			assertEquals("0", ymm0.getUnsignedValue().toString(16));

			TraceData st0;
			try (Transaction tx = tb.trace.openTransaction("Float80 unit")) {
				TraceCodeSpace code = tb.trace.getCodeManager().getCodeSpace(t1f0, true);
				st0 = code.definedData()
						.create(Lifespan.nowOn(0), tb.reg("st0"), Float10DataType.dataType);
			}

			assertEquals("0.0", st0.getDefaultValueRepresentation());
		}
	}

	@Test
	public void testCreateObj() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra trace connect %s
				ghidra trace start
				ghidra trace tx-start "Create Object"
				echo \\n---Id---\\n
				ghidra trace create-obj Test.Objects[1]
				echo \\n---
				ghidra trace tx-commit
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/noname")) {
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
				echo \\n---Lifespan---\\n
				ghidra trace insert-obj Test.Objects[1]
				echo \\n---
				ghidra trace tx-commit
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/noname")) {
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
				ghidra trace start
				ghidra trace tx-start "Create Object"
				ghidra trace create-obj Test.Objects[1]
				ghidra trace insert-obj Test.Objects[1]
				ghidra trace set-snap 1
				ghidra trace remove-obj Test.Objects[1]
				ghidra trace tx-commit
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/noname")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Test.Objects[1]"));
			assertNotNull(object);
			Lifespan life = Unique.assertOne(object.getLife().spans());
			assertEquals(Lifespan.at(0), life);
		}
	}

	@SuppressWarnings("unchecked")
	protected <T> T runTestSetValue(String extra, String gdbExpr, String gtype)
			throws Exception {
		String expPrint = DummyProc.which("expPrint");
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				start
				ghidra trace start
				ghidra trace tx-start "Create Object"
				ghidra trace create-obj Test.Objects[1]
				ghidra trace insert-obj Test.Objects[1]
				%s
				ghidra trace set-value Test.Objects[1] test "%s" %s
				ghidra trace tx-commit
				kill
				quit
				""".formatted(PREAMBLE, addr, expPrint, extra, gdbExpr, gtype));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/expPrint")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Test.Objects[1]"));
			assertNotNull(object);
			TraceObjectValue value = object.getValue(0, "test");
			return value == null ? null : (T) value.getValue();
		}
	}

	@Test
	public void testSetValueNull() throws Exception {
		assertNull(runTestSetValue("", "(void)0", ""));
	}

	@Test
	public void testSetValueBool() throws Exception {
		// C++ required for bool
		assertEquals(Boolean.TRUE, runTestSetValue("set language c++", "(bool)1", ""));
	}

	@Test
	public void testSetValueByte() throws Exception {
		assertEquals(Byte.valueOf((byte) 1), runTestSetValue("", "(char)1", ""));
	}

	@Test
	public void testSetValueChar() throws Exception {
		assertEquals(Character.valueOf('A'), runTestSetValue("", "'A'", "CHAR"));
	}

	@Test
	public void testSetValueShort() throws Exception {
		assertEquals(Short.valueOf((short) 1), runTestSetValue("", "(short)1", ""));
	}

	@Test
	public void testSetValueInt() throws Exception {
		assertEquals(Integer.valueOf(1), runTestSetValue("", "(int)1", ""));
	}

	@Test
	public void testSetValueLong() throws Exception {
		assertEquals(Long.valueOf(1), runTestSetValue("", "(long long)1", ""));
	}

	@Test
	public void testSetValueString() throws Exception {
		assertEquals("Hello World!", runTestSetValue("", "\\\"Hello World!\\\"", ""));
	}

	@Test
	public void testSetValueStringWide() throws Exception {
		// C++ required for wchar_t
		assertEquals("Hello World!",
			runTestSetValue("set language c++", "L\\\"Hello World!\\\"", ""));
	}

	@Test
	public void testSetValueBoolArr() throws Exception {
		// C++ required for bool, true, false
		assertArrayEquals(new boolean[] { true, false },
			runTestSetValue("set language c++", "{ true, false }", ""));
	}

	@Test
	public void testSetValueByteArrUsingString() throws Exception {
		// Because explicit array type is chosen, we get null terminator
		assertArrayEquals(new byte[] { 'H', 0, 'W', 0 },
			runTestSetValue("", "\\\"H\\\\0W\\\"", "BYTE_ARR"));
	}

	@Test
	public void testSetValueByteArrUsingArray() throws Exception {
		assertArrayEquals(new byte[] { 'H', 0, 'W' },
			runTestSetValue("", "(char[3]){'H', 0, 'W'}", "BYTE_ARR"));
	}

	@Test
	public void testSetValueCharArrUsingString() throws Exception {
		// Because explicit array type is chosen, we get null terminator
		assertArrayEquals(new char[] { 'H', 0, 'W', 0 },
			runTestSetValue("", "\\\"H\\\\0W\\\"", "CHAR_ARR"));
	}

	@Test
	public void testSetValueCharArrUsingArray() throws Exception {
		assertArrayEquals(new char[] { 'H', 0, 'W' },
			runTestSetValue("", "(char[3]){'H', 0, 'W'}", "CHAR_ARR"));
	}

	@Test
	public void testSetValueShortArrUsingString() throws Exception {
		// Because explicit array type is chosen, we get null terminator
		assertArrayEquals(new short[] { 'H', 0, 'W', 0 },
			runTestSetValue("set language c++", "L\\\"H\\\\0W\\\"", "SHORT_ARR"));
	}

	@Test
	public void testSetValueShortArrUsingArray() throws Exception {
		assertArrayEquals(new short[] { 'H', 0, 'W' },
			runTestSetValue("", "(short[3]){'H', 0, 'W'}", "SHORT_ARR"));
	}

	@Test
	public void testSetValueIntArrayUsingString() throws Exception {
		// Because explicit array type is chosen, we get null terminator
		assertArrayEquals(new int[] { 'H', 0, 'W', 0 },
			runTestSetValue("set language c++", "L\\\"H\\\\0W\\\"", "INT_ARR"));
	}

	@Test
	public void testSetValueIntArrUsingArray() throws Exception {
		assertArrayEquals(new int[] { 1, 2, 3, 4 },
			runTestSetValue("", "{1, 2, 3, 4}", ""));
	}

	@Test
	public void testSetValueLongArr() throws Exception {
		assertArrayEquals(new long[] { 1, 2, 3, 4 },
			runTestSetValue("", "{1LL, 2LL, 3LL, 4LL}", ""));
	}

	// Skip String[]. Trouble is expressing them in GDB....

	@Test
	public void testSetValueAddress() throws Exception {
		Address address = runTestSetValue("", "(void*)0xdeadbeef", "");
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
				file bash
				set language c++
				start
				ghidra trace start
				ghidra trace tx-start "Create Object"
				ghidra trace create-obj Test.Objects[1]
				ghidra trace insert-obj Test.Objects[1]
				ghidra trace set-value Test.Objects[1] [1] '"A"'
				ghidra trace set-value Test.Objects[1] [2] '"B"'
				ghidra trace set-value Test.Objects[1] [3] '"C"'
				ghidra trace set-snap 10
				ghidra trace retain-values Test.Objects[1] [1] [3]
				ghidra trace tx-commit
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
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
				echo \\n---Id---\\n
				ghidra trace create-obj Test.Objects[1]
				echo \\n---
				ghidra trace tx-commit
				echo \\n---GetObject---\\n
				ghidra trace get-obj Test.Objects[1]
				echo \\n---
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/noname")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Test.Objects[1]"));
			assertNotNull(object);
			String getObject = extractOutSection(out, "---GetObject---");
			assertEquals("1\tTest.Objects[1]", getObject);
		}
	}

	@Test
	public void testGetValues() throws Exception {
		String expPrint = DummyProc.which("expPrint");
		String out = runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file %s
				set language c++
				start
				ghidra trace start
				ghidra trace tx-start "Create Object"
				ghidra trace create-obj Test.Objects[1]
				ghidra trace insert-obj Test.Objects[1]
				ghidra trace set-value Test.Objects[1] vnull (void)0
				ghidra trace set-value Test.Objects[1] vbool true
				ghidra trace set-value Test.Objects[1] vbyte (char)1
				ghidra trace set-value Test.Objects[1] vchar "'A'" CHAR
				ghidra trace set-value Test.Objects[1] vshort (short)2
				ghidra trace set-value Test.Objects[1] vint 3
				ghidra trace set-value Test.Objects[1] vlong 4LL
				ghidra trace set-value Test.Objects[1] vstring '"Hello"'
				ghidra trace set-value Test.Objects[1] vboolarr '{true, false}'
				ghidra trace set-value Test.Objects[1] vbytearr '(char[3]){1, 2, 3}' BYTE_ARR
				ghidra trace set-value Test.Objects[1] vchararr '"Hello"' CHAR_ARR
				ghidra trace set-value Test.Objects[1] vshortarr '(short[3]){1, 2, 3}'
				ghidra trace set-value Test.Objects[1] vintarr '{1, 2, 3}'
				ghidra trace set-value Test.Objects[1] vlongarr '{1LL, 2LL, 3LL}'
				ghidra trace set-value Test.Objects[1] vaddr (void*)0xdeadbeef
				ghidra trace set-value Test.Objects[1] vobj Test.Objects[1] OBJECT
				ghidra trace tx-commit
				echo \\n---GetValues---\\n
				ghidra trace get-values Test.Objects[1].
				echo \\n---
				kill
				quit
				""".formatted(PREAMBLE, addr, expPrint));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/expPrint")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			assertEquals("""
					Parent          Key       Span     Value           Type
					Test.Objects[1] vaddr     [0,+inf) ram:deadbeef    ADDRESS
					Test.Objects[1] vbool     [0,+inf) True            BOOL
					Test.Objects[1] vboolarr  [0,+inf) [True, False]   BOOL_ARR
					Test.Objects[1] vbyte     [0,+inf) 1               BYTE
					Test.Objects[1] vbytearr  [0,+inf) b'\\x01\\x02\\x03' BYTE_ARR
					Test.Objects[1] vchar     [0,+inf) 'A'             CHAR
					Test.Objects[1] vchararr  [0,+inf) 'Hello\\x00'     CHAR_ARR
					Test.Objects[1] vint      [0,+inf) 3               INT
					Test.Objects[1] vintarr   [0,+inf) [1, 2, 3]       INT_ARR
					Test.Objects[1] vlong     [0,+inf) 4               LONG
					Test.Objects[1] vlongarr  [0,+inf) [1, 2, 3]       LONG_ARR
					Test.Objects[1] vobj      [0,+inf) Test.Objects[1] OBJECT
					Test.Objects[1] vshort    [0,+inf) 2               SHORT
					Test.Objects[1] vshortarr [0,+inf) [1, 2, 3]       SHORT_ARR
					Test.Objects[1] vstring   [0,+inf) 'Hello'         STRING""",
				extractOutSection(out, "---GetValues---"));
		}
	}

	@Test
	public void testGetValuesRng() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file bash
				set language c++
				start
				ghidra trace start
				ghidra trace tx-start "Create Object"
				ghidra trace create-obj Test.Objects[1]
				ghidra trace insert-obj Test.Objects[1]
				ghidra trace set-value Test.Objects[1] vaddr (void*)0xdeadbeef
				ghidra trace tx-commit
				echo \\n---GetValues---\\n
				ghidra trace get-values-rng (void*)0xdeadbeef 10
				echo \\n---
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			assertEquals("""
					Parent          Key   Span     Value        Type
					Test.Objects[1] vaddr [0,+inf) ram:deadbeef ADDRESS""",
				extractOutSection(out, "---GetValues---"));
		}
	}

	@Test
	public void testActivateObject() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file bash
				set language c++
				start
				ghidra trace start
				ghidra trace tx-start "Create Object"
				ghidra trace create-obj Test.Objects[1]
				ghidra trace insert-obj Test.Objects[1]
				ghidra trace tx-commit
				ghidra trace activate Test.Objects[1]
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
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
				file bash
				set language c++
				start
				ghidra trace start
				ghidra trace tx-start "Tx"
				ghidra trace putmem &main 10
				echo \\n---Disassemble---\\n
				ghidra trace disassemble &main
				echo \\n---
				ghidra trace tx-commit
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
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
	public void testPutInferiors() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				add-inferior
				ghidra trace start
				ghidra trace tx-start "Tx"
				ghidra trace put-inferiors
				ghidra trace tx-commit
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/noname")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Would be nice to control / validate the specifics
			Collection<TraceObject> inferiors = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(0), PathPredicates.parse("Inferiors[]"))
					.map(p -> p.getDestination(null))
					.toList();
			assertEquals(2, inferiors.size());
		}
	}

	@Test
	public void testPutAvailable() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				add-inferior
				ghidra trace start
				ghidra trace tx-start "Tx"
				ghidra trace put-available
				ghidra trace tx-commit
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/noname")) {
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
				file bash
				starti
				ghidra trace start
				ghidra trace tx-start "Tx"
				break main
				hbreak *main+10
				watch -l *((char*)(&main+20))
				rwatch -l *((char(*)[8])(&main+30))
				awatch -l *((char(*)[5])(&main+40))
				ghidra trace put-breakpoints
				ghidra trace tx-commit
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			List<TraceObjectValue> infBreakLocVals = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(0),
						PathPredicates.parse("Inferiors[1].Breakpoints[]"))
					.map(p -> p.getLastEntry())
					.sorted(Comparator.comparing(TraceObjectValue::getEntryKey))
					.toList();
			assertEquals(5, infBreakLocVals.size());
			AddressRange rangeMain =
				infBreakLocVals.get(0).getChild().getValue(0, "_range").castValue();
			Address main = rangeMain.getMinAddress();

			// NB. starti avoid use of temporary main breakpoint
			assertBreakLoc(infBreakLocVals.get(0), "[1.1]", main, 1,
				Set.of(TraceBreakpointKind.SW_EXECUTE),
				"main");
			assertBreakLoc(infBreakLocVals.get(1), "[2.1]", main.add(10), 1,
				Set.of(TraceBreakpointKind.HW_EXECUTE),
				"*main+10");
			assertBreakLoc(infBreakLocVals.get(2), "[3.1]", main.add(20), 1,
				Set.of(TraceBreakpointKind.WRITE),
				"-location *((char*)(&main+20))");
			assertBreakLoc(infBreakLocVals.get(3), "[4.1]", main.add(30), 8,
				Set.of(TraceBreakpointKind.READ),
				"-location *((char(*)[8])(&main+30))");
			assertBreakLoc(infBreakLocVals.get(4), "[5.1]", main.add(40), 5,
				Set.of(TraceBreakpointKind.READ, TraceBreakpointKind.WRITE),
				"-location *((char(*)[5])(&main+40))");
		}
	}

	@Test
	public void testPutEnvironment() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file bash
				start
				ghidra trace start
				ghidra trace tx-start "Tx"
				ghidra trace put-environment
				ghidra trace tx-commit
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Assumes GDB on Linux amd64
			TraceObject env = Objects.requireNonNull(tb.obj("Inferiors[1].Environment"));
			assertEquals("gdb", env.getValue(0, "_debugger").getValue());
			assertEquals("i386:x86-64", env.getValue(0, "_arch").getValue());
			assertEquals("GNU/Linux", env.getValue(0, "_os").getValue());
			assertEquals("little", env.getValue(0, "_endian").getValue());
		}
	}

	@Test
	public void testPutRegions() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file bash
				start
				ghidra trace start
				ghidra trace tx-start "Tx"
				ghidra trace put-regions
				ghidra trace tx-commit
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
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
				file bash
				start
				ghidra trace start
				ghidra trace tx-start "Tx"
				ghidra trace put-modules
				ghidra trace tx-commit
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Would be nice to control / validate the specifics
			Collection<? extends TraceModule> all = tb.trace.getModuleManager().getAllModules();
			TraceModule modBash =
				Unique.assertOne(all.stream().filter(m -> m.getName().contains("bash")));
			assertNotEquals(tb.addr(0), Objects.requireNonNull(modBash.getBase()));
		}
	}

	@Test
	public void testPutThreads() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file bash
				start
				ghidra trace start
				ghidra trace tx-start "Tx"
				ghidra trace put-threads
				ghidra trace tx-commit
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Would be nice to control / validate the specifics
			Unique.assertOne(tb.trace.getThreadManager().getAllThreads());
		}
	}

	@Test
	public void testPutFrames() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra trace connect %s
				file bash
				start
				break read
				continue
				ghidra trace start
				ghidra trace tx-start "Tx"
				ghidra trace put-frames
				ghidra trace tx-commit
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/gdb/bash")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Would be nice to control / validate the specifics
			List<TraceObject> stack = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(0),
						PathPredicates.parse("Inferiors[1].Threads[1].Stack[]"))
					.map(p -> p.getDestination(null))
					.toList();
			assertThat(stack.size(), greaterThan(2));
		}
	}
}
