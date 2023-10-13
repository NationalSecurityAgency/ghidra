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
import java.util.stream.IntStream;

import org.junit.Test;
import org.junit.experimental.categories.Category;

import generic.Unique;
import generic.test.category.NightlyCategory;
import ghidra.app.plugin.core.debug.utils.ManagedDomainObject;
import ghidra.dbg.util.PathPredicates;
import ghidra.debug.api.tracermi.TraceRmiAcceptor;
import ghidra.debug.api.tracermi.TraceRmiConnection;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.CodeUnit;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.*;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
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
			"Use: ghidra_trace_connect " + sockToStringForLldb(acceptor.getAddress()));
		TraceRmiConnection connection = acceptor.accept();
		Msg.info(this, "Connected: " + sockToStringForLldb(connection.getRemoteAddress()));
		connection.waitClosed();
		Msg.info(this, "Closed");
	}

	@Test
	public void testConnectErrorNoArg() throws Exception {
		try {
			runThrowError("""
					script import ghidralldb
					ghidra_trace_connect
					quit
					""");
			fail();
		}
		catch (LldbError e) {
			assertThat(e.stderr, containsString("'ghidra_trace_connect'"));
			assertThat(e.stderr, containsString("'address'"));
		}
	}

	@Test
	public void testConnect() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect %s
				quit
				""".formatted(PREAMBLE, addr));
	}

	@Test
	public void testDisconnect() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect %s
				ghidra_trace_disconnect
				quit
				""".formatted(PREAMBLE, addr));
	}

	@Test
	public void testStartTraceDefaults() throws Exception {
		// Default name and lcsp
		runThrowError(addr -> """
				%s
				ghidra_trace_connect %s
				file bash
				ghidra_trace_start
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
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
				ghidra_trace_connect %s
				ghidra_trace_start
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
					ghidra_trace_connect %s
					file bash
					script ghidralldb.util.set_convenience_variable('ghidra-language','Toy:BE:64:default')
					script ghidralldb.util.set_convenience_variable('ghidra-compiler','default')
					ghidra_trace_start myToy
					quit
					"""
					.formatted(PREAMBLE, addr));
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
		// TODO: This test assumes lldb and the target file bash are x86-64
		runThrowError(addr -> """
				%s
				ghidra_trace_connect %s
				file bash
				ghidra_trace_start
				ghidra_trace_stop
				quit
				""".formatted(PREAMBLE, addr));
		DomainFile dfBash = env.getProject().getProjectData().getFile("/New Traces/lldb/bash");
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
					file bash
					%s
					_mark_ ---Import---
					ghidra_trace_info
					ghidra_trace_connect %s
					_mark_ ---Connect---
					ghidra_trace_info
					ghidra_trace_start
					_mark_ ---Start---
					ghidra_trace_info
					ghidra_trace_stop
					_mark_ ---Stop---
					ghidra_trace_info
					ghidra_trace_disconnect
					_mark_ ---Disconnect---
					ghidra_trace_info
					quit
					""".formatted(PREAMBLE, addr);
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
		// TODO: This test assumes x86-64 on test system
		String out = runThrowError(
			"""
					script import ghidralldb
					_mark_ ---Import---
					ghidra_trace_info_lcsp
					_mark_ ---
					file bash
					_mark_ ---File---
					ghidra_trace_info_lcsp
					script ghidralldb.util.set_convenience_variable('ghidra-language','Toy:BE:64:default')
					_mark_ ---Language---
					ghidra_trace_info_lcsp
					script ghidralldb.util.set_convenience_variable('ghidra-compiler','posStack')
					_mark_ ---Compiler---
					ghidra_trace_info_lcsp
					quit
					""");

//		assertEquals("""
//				Selected Ghidra language: DATA:LE:64:default
//				Selected Ghidra compiler: pointer64""",
//			extractOutSection(out, "---Import---"));
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
				ghidra_trace_connect %s
				file bash
				ghidra_trace_start no-save
				ghidra_trace_txstart "Create snapshot"
				ghidra_trace_new_snap "Scripted snapshot"
				ghidra_trace_txcommit
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/no-save")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			assertEquals(0, tb.trace.getTimeManager().getAllSnapshots().size());
		}

		runThrowError(addr -> """
				%s
				ghidra_trace_connect %s
				file bash
				ghidra_trace_start save
				ghidra_trace_txstart "Create snapshot"
				ghidra_trace_new_snap "Scripted snapshot"
				ghidra_trace_txcommit
				ghidra_trace_save
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
				ghidra_trace_connect %s
				file bash
				ghidra_trace_start
				ghidra_trace_txstart "Create snapshot"
				ghidra_trace_new_snap "Scripted snapshot"
				ghidra_trace_txcommit
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceSnapshot snapshot = Unique.assertOne(tb.trace.getTimeManager().getAllSnapshots());
			assertEquals(0, snapshot.getKey());
			assertEquals("\"Scripted snapshot\"", snapshot.getDescription());
		}
	}

	@Test
	public void testPutmem() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra_trace_connect %s
				file bash
				process launch --stop-at-entry
				ghidra_trace_start
				ghidra_trace_txstart "Create snapshot"
				ghidra_trace_new_snap "Scripted snapshot"
				ghidra_trace_putmem `(void(*)())main` 10
				ghidra_trace_txcommit
				_mark_ ---Dump---
				x/10bx `(void(*)())main`
				_mark_ ---")
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = Unique.assertOne(tb.trace.getTimeManager().getAllSnapshots()).getKey();

			MemDump dump = parseHexDump(extractOutSection(out, "---Dump---"));
			ByteBuffer buf = ByteBuffer.allocate(dump.data().length);
			tb.trace.getMemoryManager().getBytes(snap, tb.addr(dump.address()), buf);

			assertArrayEquals(dump.data(), buf.array());
		}
	}

	// Not sure this is a meaningful test anymore
	@Test
	public void testPutmemProcess2() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra_trace_connect %s
				file bash
				process launch --stop-at-entry
				ghidra_trace_start
				ghidra_trace_txstart "Create snapshot"
				ghidra_trace_new_snap "Scripted snapshot"
				ghidra_trace_putmem `(void(*)())main` 10
				ghidra_trace_txcommit
				_mark_ ---Dump---
				x/10bx `(void(*)())main`
				_mark_ ---")
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			AddressSpace ram2 = tb.trace.getBaseAddressFactory().getAddressSpace("ram");
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
				settings set interpreter.echo-commands false
				%s
				ghidra_trace_connect %s
				file bash
				process launch --stop-at-entry
				ghidra_trace_start
				ghidra_trace_txstart "Create snapshot"
				ghidra_trace_new_snap "Scripted snapshot"
				ghidra_trace_putmem_state `(void(*)())main` 10 error
				ghidra_trace_txcommit
				_mark_ ---Start---
				print/x (void(*)())main
				_mark_ ---")
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = Unique.assertOne(tb.trace.getTimeManager().getAllSnapshots()).getKey();

			String eval = extractOutSection(out, "---Start---");
			String addrstr = eval.split("=")[1].trim();
			if (addrstr.contains(" ")) {
				addrstr = addrstr.substring(0, addrstr.indexOf(" "));
			}
			Address addr = tb.addr(Long.decode(addrstr));

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
				ghidra_trace_connect %s
				file bash
				process launch --stop-at-entry
				ghidra_trace_start
				ghidra_trace_txstart "Create snapshot"
				ghidra_trace_new_snap "Scripted snapshot"
				ghidra_trace_putmem `(void(*)())main` 10
				ghidra_trace_delmem `(void(*)())main` 5
				ghidra_trace_txcommit
				_mark_ ---Dump---
				x/10bx (void(*)())main
				_mark_ ---")
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
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
				ghidra_trace_connect %s
				file bash
				process launch --stop-at-entry
				ghidra_trace_start
				expr $rax = 0xdeadbeef
				#expr $ymm0 = %s
				expr $st0 = 1.5
				ghidra_trace_txstart "Create snapshot"
				ghidra_trace_new_snap "Scripted snapshot"
				ghidra_trace_putreg
				ghidra_trace_txcommit
				kill
				quit
				""".formatted(PREAMBLE, addr, count));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
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

			RegisterValue rax = regs.getValue(snap, tb.reg("rax"));
			assertEquals("deadbeef", rax.getUnsignedValue().toString(16));

//			RegisterValue ymm0 = regs.getValue(snap, tb.reg("ymm0"));
//			// LLDB treats registers in arch's endian
//			assertEquals("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
//				ymm0.getUnsignedValue().toString(16));

//			TraceData st0;
//			try (Transaction tx = tb.trace.openTransaction("Float80 unit")) {
//				TraceCodeSpace code = tb.trace.getCodeManager().getCodeSpace(t1f0, true);
//				st0 = code.definedData()
//						.create(Lifespan.nowOn(0), tb.reg("st0"), Float10DataType.dataType);
//			}
//			assertEquals("1.5", st0.getDefaultValueRepresentation());
		}
	}

	@Test
	public void testDelreg() throws Exception {
		String count = IntStream.iterate(0, i -> i < 32, i -> i + 1)
				.mapToObj(Integer::toString)
				.collect(Collectors.joining(",", "{", "}"));
		runThrowError(addr -> """
				%s
				ghidra_trace_connect %s
				file bash
				process launch --stop-at-entry
				ghidra_trace_start
				#expr $ymm0 = %s
				expr $st0 = 1.5
				ghidra_trace_txstart "Create snapshot"
				ghidra_trace_new_snap "Scripted snapshot"
				ghidra_trace_putreg
				ghidra_trace_delreg
				ghidra_trace_txcommit
				kill
				quit
				""".formatted(PREAMBLE, addr, count));
		// The spaces will be left over, but the values should be zeroed
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
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

			RegisterValue rax = regs.getValue(snap, tb.reg("rax"));
			assertEquals("0", rax.getUnsignedValue().toString(16));

//			RegisterValue ymm0 = regs.getValue(snap, tb.reg("ymm0"));
//			assertEquals("0", ymm0.getUnsignedValue().toString(16));

//			TraceData st0;
//			try (Transaction tx = tb.trace.openTransaction("Float80 unit")) {
//				TraceCodeSpace code = tb.trace.getCodeManager().getCodeSpace(t1f0, true);
//				st0 = code.definedData()
//						.create(Lifespan.nowOn(0), tb.reg("st0"), Float10DataType.dataType);
//			}
//			assertEquals("0.0", st0.getDefaultValueRepresentation());
		}
	}

	@Test
	public void testCreateObj() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra_trace_connect %s
				ghidra_trace_start
				ghidra_trace_txstart "Create Object"
				_mark_ ---Id---
				ghidra_trace_create_obj Test.Objects[1]
				_mark_ ---")
				ghidra_trace_txcommit
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
				ghidra_trace_connect %s
				ghidra_trace_start
				ghidra_trace_txstart "Create Object"
				ghidra_trace_create_obj Test.Objects[1]
				_mark_ ---Lifespan---
				ghidra_trace_insert_obj Test.Objects[1]
				_mark_ ---")
				ghidra_trace_txcommit
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
				ghidra_trace_connect %s
				file bash
				process launch --stop-at-entry
				ghidra_trace_start
				ghidra_trace_txstart "Create Object"
				ghidra_trace_create_obj Test.Objects[1]
				ghidra_trace_insert_obj Test.Objects[1]
				ghidra_trace_set_snap 1
				ghidra_trace_remove_obj Test.Objects[1]
				ghidra_trace_txcommit
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
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
				ghidra_trace_connect %s
				file bash
				process launch --stop-at-entry
				ghidra_trace_start
				ghidra_trace_txstart "Create Object"
				ghidra_trace_create_obj Test.Objects[1]
				ghidra_trace_insert_obj Test.Objects[1]
				%s
				ghidra_trace_set_value Test.Objects[1] test %s %s
				ghidra_trace_txcommit
				kill
				quit
				""".formatted(PREAMBLE, addr, extra, lldbExpr, gtype));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
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
		assertNull(runTestSetValue("", "(void)null", ""));
	}

	@Test
	public void testSetValueBool() throws Exception {
		// C++ required for bool
		assertEquals(Boolean.TRUE, runTestSetValue("#set language c++", "(bool)1", ""));
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
		assertEquals(Long.valueOf(1), runTestSetValue("", "(long)1", ""));
	}

	@Test
	public void testSetValueString() throws Exception {
		assertEquals("\"Hello World!\"", runTestSetValue("", "\"Hello World!\"", ""));
	}

	@Test
	public void testSetValueStringWide() throws Exception {
		assertEquals("L\"Hello World!\"", runTestSetValue("", "L\"Hello World!\"", ""));
	}

	@Test
	public void testSetValueBoolArr() throws Exception {
		// C++ required for bool, true, false
		assertArrayEquals(new boolean[] { true, false },
			runTestSetValue("expr bool $x[2]={ true, false }", "$x", ""));
	}

	@Test
	public void testSetValueByteArrUsingString() throws Exception {
		// Because explicit array type is chosen, we get null terminator
		assertArrayEquals(new byte[] { 'H', 0, 'W', 0 },
			runTestSetValue("expr char $x[]=\"H\\0W\"", "$x", "BYTE_ARR"));
	}

	@Test
	public void testSetValueByteArrUsingArray() throws Exception {
		assertArrayEquals(new byte[] { 'H', 0, 'W' },
			runTestSetValue("expr char $x[]={'H', 0, 'W'}", "$x", "BYTE_ARR"));
	}

	@Test
	public void testSetValueCharArrUsingString() throws Exception {
		// Because explicit array type is chosen, we get null terminator
		assertArrayEquals(new char[] { 'H', 0, 'W', 0 },
			runTestSetValue("expr char $x[]=\"H\\0W\"", "$x", "CHAR_ARR"));
	}

	@Test
	public void testSetValueCharArrUsingArray() throws Exception {
		assertArrayEquals(new char[] { 'H', 0, 'W' },
			runTestSetValue("expr char $x[]={'H', 0, 'W'}", "$x", "CHAR_ARR"));
	}

	@Test
	public void testSetValueShortArrUsingString() throws Exception {
		// Because explicit array type is chosen, we get null terminator
		assertArrayEquals(new short[] { 'H', 0, 'W', 0 },
			runTestSetValue("expr wchar_t $x[]=L\"H\\0W\"", "$x", "SHORT_ARR"));
	}

	@Test
	public void testSetValueShortArrUsingArray() throws Exception {
		assertArrayEquals(new short[] { 'H', 0, 'W' },
			runTestSetValue("expr short $x[]={'H', 0, 'W'}", "$x", "SHORT_ARR"));
	}

	@Test
	public void testSetValueIntArrayUsingMixedArray() throws Exception {
		// Because explicit array type is chosen, we get null terminator
		assertArrayEquals(new int[] { 'H', 0, 'W' },
			runTestSetValue("expr int $x[]={'H', 0, 'W'}", "$x", "INT_ARR"));
	}

	@Test
	public void testSetValueIntArrUsingArray() throws Exception {
		assertArrayEquals(new int[] { 1, 2, 3, 4 },
			runTestSetValue("expr int $x[]={1,2,3,4}", "$x", ""));
	}

	@Test
	public void testSetValueLongArr() throws Exception {
		assertArrayEquals(new long[] { 1, 2, 3, 4 },
			runTestSetValue("expr long long $x[]={1LL,2LL,3LL,4LL}", "$x", ""));
	}

	// Skip String[]. Trouble is expressing them in LLDB....

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
				ghidra_trace_connect %s
				file bash
				#set language c++
				process launch --stop-at-entry
				ghidra_trace_start
				ghidra_trace_txstart "Create Object"
				ghidra_trace_create_obj Test.Objects[1]
				ghidra_trace_insert_obj Test.Objects[1]
				ghidra_trace_set_value Test.Objects[1] [1] '"A"'
				ghidra_trace_set_value Test.Objects[1] [2] '"B"'
				ghidra_trace_set_value Test.Objects[1] [3] '"C"'
				ghidra_trace_set_snap 10
				ghidra_trace_retain_values Test.Objects[1] [1] [3]
				ghidra_trace_txcommit
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Test.Objects[1]"));
			assertNotNull(object);
			assertEquals(Map.ofEntries(
				Map.entry("[1]", Lifespan.nowOn(0)),
				Map.entry("[2]", Lifespan.span(0, 9)),
				Map.entry("[3]", Lifespan.nowOn(0))),
				object.getValues()
						.stream()
						.collect(Collectors.toMap(v -> v.getEntryKey(), v -> v.getLifespan())));
		}
	}

	@Test
	public void testGetObj() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra_trace_connect %s
				ghidra_trace_start
				ghidra_trace_txstart "Create Object"
				_mark_ ---Id---
				ghidra_trace_create_obj Test.Objects[1]
				_mark_ ---")
				ghidra_trace_txcommit
				_mark_ ---GetObject---
				ghidra_trace_get_obj Test.Objects[1]
				_mark_ ---")
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/noname")) {
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
		String out = runThrowError(addr -> """
				%s
				ghidra_trace_connect %s
				file bash
				process launch --stop-at-entry
				ghidra_trace_start
				ghidra_trace_txstart "Create Object"
				ghidra_trace_create_obj Test.Objects[1]
				ghidra_trace_insert_obj Test.Objects[1]
				#ghidra_trace_set_value Test.Objects[1] vnull (void)null
				ghidra_trace_set_value Test.Objects[1] vbool true
				ghidra_trace_set_value Test.Objects[1] vbyte (char)1
				ghidra_trace_set_value Test.Objects[1] vchar 'A' CHAR
				ghidra_trace_set_value Test.Objects[1] vshort (short)2
				ghidra_trace_set_value Test.Objects[1] vint 3
				ghidra_trace_set_value Test.Objects[1] vlong 4LL
				ghidra_trace_set_value Test.Objects[1] vstring "Hello"
				expr bool $vboolarr[] = {true, false}
				ghidra_trace_set_value Test.Objects[1] vboolarr $vboolarr
				expr char $vbytearr[] = {1, 2, 3}
				ghidra_trace_set_value Test.Objects[1] vbytearr $vbytearr BYTE_ARR
				expr char $vchararr[] = "Hello"
				ghidra_trace_set_value Test.Objects[1] vchararr $vchararr CHAR_ARR
				expr short $vshortarr[] = {1, 2, 3}
				ghidra_trace_set_value Test.Objects[1] vshortarr $vshortarr
				expr int $vintarr[] = {1, 2, 3}
				ghidra_trace_set_value Test.Objects[1] vintarr $vintarr
				expr long $vlongarr[] = {1LL, 2LL, 3LL}
				ghidra_trace_set_value Test.Objects[1] vlongarr $vlongarr
				ghidra_trace_set_value Test.Objects[1] vaddr (void*)0xdeadbeef
				ghidra_trace_set_value Test.Objects[1] vobj Test.Objects[1] OBJECT
				ghidra_trace_txcommit
				_mark_ ---GetValues---
				ghidra_trace_get_values Test.Objects[1].
				_mark_ ---")
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			assertEquals(
				"""
						Parent          Key       Span     Value           Type
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
						Test.Objects[1] vstring   [0,+inf) '"Hello"'         STRING
						Test.Objects[1] vaddr     [0,+inf) ram:deadbeef    ADDRESS"""
						.replaceAll(" ", "")
						.replaceAll("\n", ""),
				extractOutSection(out, "---GetValues---").replaceAll(" ", "").replaceAll("\n", ""));
		}
	}

	@Test
	public void testGetValuesRng() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra_trace_connect %s
				file bash
				#set language c++
				process launch --stop-at-entry
				ghidra_trace_start
				ghidra_trace_txstart "Create Object"
				ghidra_trace_create_obj Test.Objects[1]
				ghidra_trace_insert_obj Test.Objects[1]
				ghidra_trace_set_value Test.Objects[1] vaddr (void*)0xdeadbeef
				ghidra_trace_txcommit
				_mark_ ---GetValues---
				ghidra_trace_get_values_rng (void*)0xdeadbeef 10
				_mark_ ---")
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			assertEquals("""
					Parent
					Key
					Span
					Value
					Type
					Test.Objects[1]
					vaddr
					[0,+inf)
					ram:deadbeef
					ADDRESS""".replaceAll(" ", ""),
				extractOutSection(out, "---GetValues---").replaceAll(" ", ""));
		}
	}

	//@Test
	public void testActivateObject() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect %s
				file bash
				#set language c++
				process launch --stop-at-entry
				ghidra_trace_start
				ghidra_trace_txstart "Create Object"
				ghidra_trace_create_obj Test.Objects[1]
				ghidra_trace_insert_obj Test.Objects[1]
				ghidra_trace_txcommit
				ghidra_trace_activate Test.Objects[1]
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
			assertSame(mdo.get(), traceManager.getCurrentTrace());
			assertEquals("Test.Objects[1]",
				traceManager.getCurrentObject().getCanonicalPath().toString());
		}
	}

	@Test
	public void testDisassemble() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra_trace_connect %s
				file bash
				#set language c++
				process launch --stop-at-entry
				ghidra_trace_start
				ghidra_trace_txstart "Tx"
				ghidra_trace_putmem `(void(*)())main` 10
				_mark_ ---Disassemble---
				ghidra_trace_disassemble `(void(*)())main`
				_mark_ ---")
				ghidra_trace_txcommit
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
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
				ghidra_trace_connect %s
				ghidra_trace_start
				ghidra_trace_txstart "Tx"
				ghidra_trace_put_processes
				ghidra_trace_txcommit
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
				ghidra_trace_connect %s
				ghidra_trace_start
				ghidra_trace_txstart "Tx"
				ghidra_trace_put_available
				ghidra_trace_txcommit
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
				ghidra_trace_connect %s
				file bash
				process launch --stop-at-entry
				ghidra_trace_start
				ghidra_trace_txstart "Tx"
				breakpoint set --name main
				breakpoint set -H --name main
				ghidra_trace_put_breakpoints
				ghidra_trace_txcommit
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			List<TraceObjectValue> procBreakLocVals = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(0),
						PathPredicates.parse("Processes[].Breakpoints[]"))
					.map(p -> p.getLastEntry())
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
				ghidra_trace_connect %s
				file bash
				process launch --stop-at-entry
				ghidra_trace_start
				ghidra_trace_txstart "Tx"
				watchpoint set expression -- `(void(*)())main`
				watchpoint set expression -w read -- `(void(*)())main`+-0x20
				watchpoint set expression -w read_write -- `(void(*)())main`+0x30
				ghidra_trace_put_watchpoints
				ghidra_trace_txcommit
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			List<TraceObjectValue> procWatchLocVals = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(0),
						PathPredicates.parse("Processes[].Watchpoints[]"))
					.map(p -> p.getLastEntry())
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
				ghidra_trace_connect %s
				file bash
				process launch --stop-at-entry
				ghidra_trace_start
				ghidra_trace_txstart "Tx"
				ghidra_trace_put_environment
				ghidra_trace_txcommit
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Assumes LLDB on Linux amd64
			TraceObject env =
				Objects.requireNonNull(tb.objAny("Processes[].Environment", Lifespan.at(0)));
			assertEquals("lldb", env.getValue(0, "_debugger").getValue());
			assertEquals("x86_64", env.getValue(0, "_arch").getValue());
			assertEquals("linux", env.getValue(0, "_os").getValue());
			assertEquals("little", env.getValue(0, "_endian").getValue());
		}
	}

	@Test
	public void testPutRegions() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect %s
				file bash
				process launch --stop-at-entry
				ghidra_trace_start
				ghidra_trace_txstart "Tx"
				ghidra_trace_put_regions
				ghidra_trace_txcommit
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
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
				ghidra_trace_connect %s
				file bash
				process launch --stop-at-entry
				ghidra_trace_start
				ghidra_trace_txstart "Tx"
				ghidra_trace_put_modules
				ghidra_trace_txcommit
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
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
				ghidra_trace_connect %s
				file bash
				process launch --stop-at-entry
				ghidra_trace_start
				ghidra_trace_txstart "Tx"
				ghidra_trace_put_threads
				ghidra_trace_txcommit
				kill
				quit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Would be nice to control / validate the specifics
			Unique.assertOne(tb.trace.getThreadManager().getAllThreads());
		}
	}

	@Test
	public void testPutFrames() throws Exception {
		try (LldbAndConnection conn = startAndConnectLldb()) {
			conn.execute("file bash");
			conn.execute("ghidra_trace_start");
			conn.execute("ghidra_trace_txstart 'Tx'");
			conn.execute("ghidra_trace_put_processes");
			conn.execute("ghidra_trace_txcommit");
			conn.execute("ghidra_trace_install_hooks");
			conn.execute("breakpoint set -n read");
			conn.execute("run");

			try (ManagedDomainObject mdo = openDomainObject("/New Traces/lldb/bash")) {
				tb = new ToyDBTraceBuilder((Trace) mdo.get());

				waitStopped();
				conn.execute("ghidra_trace_txstart 'Tx'");
				conn.execute("ghidra_trace_put_frames");
				conn.execute("ghidra_trace_txcommit");
				conn.execute("kill");
				conn.execute("quit");
				// Would be nice to control / validate the specifics
				List<TraceObject> stack = tb.trace.getObjectManager()
						.getValuePaths(Lifespan.at(0),
							PathPredicates.parse("Processes[].Threads[].Stack[]"))
						.map(p -> p.getDestination(null))
						.toList();
				assertThat(stack.size(), greaterThan(2));
			}
		}
	}

	@Test
	public void testMinimal() throws Exception {
		Function<String, String> scriptSupplier = addr -> """
				%s
				ghidra_trace_connect %s
				""".formatted(PREAMBLE, addr);
		try (LldbAndConnection conn = startAndConnectLldb(scriptSupplier)) {
			conn.execute("script print('FINISHED')");
			conn.execute("quit");
		}
	}
}
