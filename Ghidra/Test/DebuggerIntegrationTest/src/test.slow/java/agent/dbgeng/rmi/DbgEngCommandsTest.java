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
package agent.dbgeng.rmi;

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

import generic.Unique;
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
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.Msg;

public class DbgEngCommandsTest extends AbstractDbgEngTraceRmiTest {

	//@Test
	public void testManual() throws Exception {
		TraceRmiAcceptor acceptor = traceRmi.acceptOne(null);
		Msg.info(this,
			"Use: ghidra_trace_connect(" + sockToStringForPython(acceptor.getAddress()) + ")");
		TraceRmiConnection connection = acceptor.accept();
		Msg.info(this, "Connected: " + sockToStringForPython(connection.getRemoteAddress()));
		connection.waitClosed();
		Msg.info(this, "Closed");
	}

	@Test
	public void testConnectErrorNoArg() throws Exception {
		try {
			runThrowError("""
					from ghidradbg.commands import *
					ghidra_trace_connect()
					quit()
					""");
			fail();
		}
		catch (PythonError e) {
			assertThat(e.stderr, containsString("'ghidra_trace_connect'"));
			assertThat(e.stderr, containsString("'address'"));
		}
	}

	@Test
	public void testConnect() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				quit()
				""".formatted(PREAMBLE, addr));
	}

	@Test
	public void testDisconnect() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_disconnect()
				quit()
				""".formatted(PREAMBLE, addr));
	}

	@Test
	public void testStartTraceDefaults() throws Exception {
		// Default name and lcsp
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create('notepad.exe')
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			assertEquals("x86:LE:64:default",
				tb.trace.getBaseLanguage().getLanguageID().getIdAsString());
			assertEquals("windows",
				tb.trace.getBaseCompilerSpec().getCompilerSpecID().getIdAsString());
		}
	}

	@Test
	public void testStartTraceDefaultNoFile() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_start()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/noname")) {
			assertThat(mdo.get(), instanceOf(Trace.class));
		}
	}

	@Test
	public void testStartTraceCustomize() throws Exception {
		runThrowError(
			addr -> """
					%s
					ghidra_trace_connect('%s')
					ghidra_trace_create('notepad.exe', start_trace=False)
					util.set_convenience_variable('ghidra-language','Toy:BE:64:default')
					util.set_convenience_variable('ghidra-compiler','default')
					ghidra_trace_start('myToy')
					quit()
					"""
					.formatted(PREAMBLE, addr));
		DomainFile dfMyToy = env.getProject().getProjectData().getFile("/New Traces/pydbg/myToy");
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
		// TODO: This test assumes pydbg and the target file notepad are x86-64
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create('notepad.exe')
				ghidra_trace_stop()
				quit()
				""".formatted(PREAMBLE, addr));
		DomainFile dfBash =
			env.getProject().getProjectData().getFile("/New Traces/pydbg/notepad.exe");
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
					print('---Import---')
					ghidra_trace_info()
					ghidra_trace_connect('%s')
					print('---Connect---')
					ghidra_trace_info()
					ghidra_trace_create('notepad.exe')
					print('---Start---')
					ghidra_trace_info()
					ghidra_trace_stop()
					print('---Stop---')
					ghidra_trace_info()
					ghidra_trace_disconnect()
					print('---Disconnect---')
					ghidra_trace_info()
					quit()
					""".formatted(PREAMBLE, addr);
		});

		assertEquals("""
				Not connected to Ghidra""",
			extractOutSection(out, "---Import---"));
		assertEquals("""
				Connected to Ghidra at %s

				No trace""".formatted(refAddr.get()),
			extractOutSection(out, "---Connect---").replaceAll("\r", "").substring(0, 48));
		String expected = """
				Connected to Ghidra at %s

				Trace active""".formatted(refAddr.get());
		String actual = extractOutSection(out, "---Start---").replaceAll("\r", "");
		assertEquals(expected, actual.substring(0, expected.length()));
		assertEquals("""
				Connected to Ghidra at %s

				No trace""".formatted(refAddr.get()),
			extractOutSection(out, "---Stop---").replaceAll("\r", ""));
		assertEquals("""
				Not connected to Ghidra""",
			extractOutSection(out, "---Disconnect---"));
	}

	@Test
	public void testLcsp() throws Exception {
		// TODO: This test assumes x86-64 on test system
		String out = runThrowError(
			"""
					%s
					print('---Import---')
					ghidra_trace_info_lcsp()
					print('---')
					ghidra_trace_create('notepad.exe', start_trace=False)
					print('---File---')
					ghidra_trace_info_lcsp()
					util.set_convenience_variable('ghidra-language','Toy:BE:64:default')
					print('---Language---')
					ghidra_trace_info_lcsp()
					util.set_convenience_variable('ghidra-compiler','posStack')
					print('---Compiler---')
					ghidra_trace_info_lcsp()
					quit()
					""".formatted(PREAMBLE));

		assertTrue(
			extractOutSection(out, "---File---").replaceAll("\r", "")
					.contains(
						"""
								Selected Ghidra language: x86:LE:64:default

								Selected Ghidra compiler: windows"""));
		assertEquals("""
				Selected Ghidra language: Toy:BE:64:default

				Selected Ghidra compiler: default""",
			extractOutSection(out, "---Language---").replaceAll("\r", ""));
		assertEquals("""
				Selected Ghidra language: Toy:BE:64:default

				Selected Ghidra compiler: posStack""",
			extractOutSection(out, "---Compiler---").replaceAll("\r", ""));
	}

	//@Test TODO - revisit after rebasing on master
	public void testSave() throws Exception {
		traceManager.setSaveTracesByDefault(false);

		// For sanity check, verify failing to save drops data
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create('notepad.exe')
				ghidra_trace_txstart('Create snapshot')
				ghidra_trace_new_snap('Scripted snapshot')
				ghidra_trace_txcommit()
				ghidra_trace_stop()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			assertEquals(0, tb.trace.getTimeManager().getAllSnapshots().size());
		}

		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create('notepad.exe')
				ghidra_trace_txstart('Create snapshot')
				ghidra_trace_new_snap('Scripted snapshot')
				ghidra_trace_txcommit()
				ghidra_trace_save()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			assertEquals(1, tb.trace.getTimeManager().getAllSnapshots().size());
		}
	}

	@Test
	public void testSnapshot() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create('notepad.exe')
				ghidra_trace_txstart('Create snapshot')
				ghidra_trace_new_snap('Scripted snapshot')
				ghidra_trace_txcommit()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
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
				ghidra_trace_connect('%s')
				ghidra_trace_create('notepad.exe')
				ghidra_trace_txstart('Create snapshot')
				ghidra_trace_new_snap('Scripted snapshot')
				ghidra_trace_putmem('$pc 16')
				ghidra_trace_txcommit()
				print('---Dump---')
				pc = util.get_debugger().reg.get_pc()
				util.get_debugger().dd(pc, count=1)
				print('---')
				ghidra_trace_kill()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = Unique.assertOne(tb.trace.getTimeManager().getAllSnapshots()).getKey();

			MemDump dump = parseHexDump(extractOutSection(out, "---Dump---"));
			ByteBuffer buf = ByteBuffer.allocate(dump.data().length);
			tb.trace.getMemoryManager().getBytes(snap, tb.addr(dump.address()), buf);

			assertArrayEquals(dump.data(), buf.array());
		}
	}

	@Test
	public void testPutmemState() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create('notepad.exe')
				ghidra_trace_txstart('Create snapshot')
				ghidra_trace_new_snap('Scripted snapshot')
				ghidra_trace_putmem_state('$pc 16 error')
				ghidra_trace_txcommit()
				print('---Start---')
				pc = util.get_debugger().reg.get_pc()
				util.get_debugger().dd(pc, count=1)
				print('---')
				ghidra_trace_kill()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = Unique.assertOne(tb.trace.getTimeManager().getAllSnapshots()).getKey();

			String eval = extractOutSection(out, "---Start---");
			String addrstr = eval.substring(0, eval.indexOf(":")).trim();
			Address addr = tb.addr(Long.parseLong(addrstr, 16));

			Entry<TraceAddressSnapRange, TraceMemoryState> entry =
				tb.trace.getMemoryManager().getMostRecentStateEntry(snap, addr);
			assertEquals(Map.entry(new ImmutableTraceAddressSnapRange(
				new AddressRangeImpl(addr, 16), Lifespan.at(0)), TraceMemoryState.ERROR), entry);
		}
	}

	@Test
	public void testDelmem() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create('notepad.exe')
				ghidra_trace_txstart('Create snapshot')
				ghidra_trace_new_snap('Scripted snapshot')
				ghidra_trace_putmem('$pc 16')
				ghidra_trace_delmem('$pc 8')
				ghidra_trace_txcommit()
				print('---Dump---')
				pc = util.get_debugger().reg.get_pc()
				util.get_debugger().dd(pc, count=1)
				print('---')
				ghidra_trace_kill()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = Unique.assertOne(tb.trace.getTimeManager().getAllSnapshots()).getKey();

			MemDump dump = parseHexDump(extractOutSection(out, "---Dump---"));
			Arrays.fill(dump.data(), 0, 8, (byte) 0);
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
				ghidra_trace_connect('%s')
				ghidra_trace_create('notepad.exe')
				regs = util.get_debugger().reg
				regs._set_register("rax", int(0xdeadbeef))
				regs._set_register("st0", int(1.5))
				ghidra_trace_txstart('Create snapshot')
				ghidra_trace_new_snap('Scripted snapshot')
				ghidra_trace_putreg()
				ghidra_trace_txcommit()
				ghidra_trace_kill()
				quit()
				""".formatted(PREAMBLE, addr, count));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = Unique.assertOne(tb.trace.getTimeManager().getAllSnapshots()).getKey();
			List<TraceObjectValue> regVals = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(0),
						PathPredicates.parse("Processes[].Threads[].Registers"))
					.map(p -> p.getLastEntry())
					.toList();
			TraceObjectValue tobj = regVals.get(0);
			AddressSpace t1f0 = tb.trace.getBaseAddressFactory()
					.getAddressSpace(tobj.getCanonicalPath().toString());
			TraceMemorySpace regs = tb.trace.getMemoryManager().getMemorySpace(t1f0, false);

			RegisterValue rax = regs.getValue(snap, tb.reg("rax"));
			assertEquals("deadbeef", rax.getUnsignedValue().toString(16));

			// TODO:  Pybag currently doesn't suppport non-int assignments
			/*
			 * // RegisterValue ymm0 = regs.getValue(snap, tb.reg("ymm0")); // // LLDB
			 * treats registers in arch's endian // assertEquals(
			 * "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100", //
			 * ymm0.getUnsignedValue().toString(16));
			 * 
			 * // TraceData st0; // try (Transaction tx =
			 * tb.trace.openTransaction("Float80 unit")) { // TraceCodeSpace code =
			 * tb.trace.getCodeManager().getCodeSpace(t1f0, true); // st0 =
			 * code.definedData() // .create(Lifespan.nowOn(0), tb.reg("st0"),
			 * Float10DataType.dataType); // } // assertEquals("1.5",
			 * st0.getDefaultValueRepresentation());
			 */
		}
	}

	@Test
	public void testDelreg() throws Exception {
		String count = IntStream.iterate(0, i -> i < 32, i -> i + 1)
				.mapToObj(Integer::toString)
				.collect(Collectors.joining(",", "{", "}"));
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create('notepad.exe')
				regs = util.get_debugger().reg
				regs._set_register("st0", int(1.5))
				ghidra_trace_txstart('Create snapshot')
				ghidra_trace_new_snap('Scripted snapshot')
				ghidra_trace_putreg()
				ghidra_trace_delreg()
				ghidra_trace_txcommit()
				ghidra_trace_kill()
				quit()
				""".formatted(PREAMBLE, addr, count));
		// The spaces will be left over, but the values should be zeroed
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = Unique.assertOne(tb.trace.getTimeManager().getAllSnapshots()).getKey();
			List<TraceObjectValue> regVals = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(0),
						PathPredicates.parse("Processes[].Threads[].Registers"))
					.map(p -> p.getLastEntry())
					.toList();
			TraceObjectValue tobj = regVals.get(0);
			AddressSpace t1f0 = tb.trace.getBaseAddressFactory()
					.getAddressSpace(tobj.getCanonicalPath().toString());
			TraceMemorySpace regs = tb.trace.getMemoryManager().getMemorySpace(t1f0, false);

			RegisterValue rax = regs.getValue(snap, tb.reg("rax"));
			assertEquals("0", rax.getUnsignedValue().toString(16));

			// TODO: As above, not currently supported by pybag
			/*
			 * // RegisterValue ymm0 = regs.getValue(snap, tb.reg("ymm0")); //
			 * assertEquals("0", ymm0.getUnsignedValue().toString(16));
			 * 
			 * // TraceData st0; // try (Transaction tx =
			 * tb.trace.openTransaction("Float80 unit")) { // TraceCodeSpace code =
			 * tb.trace.getCodeManager().getCodeSpace(t1f0, true); // st0 =
			 * code.definedData() // .create(Lifespan.nowOn(0), tb.reg("st0"),
			 * Float10DataType.dataType); // } // assertEquals("0.0",
			 * st0.getDefaultValueRepresentation());
			 */
		}
	}

	@Test
	public void testCreateObj() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_start()
				ghidra_trace_txstart('Create Object')
				print('---Id---')
				ghidra_trace_create_obj('Test.Objects[1]')
				print('---')
				ghidra_trace_txcommit()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/noname")) {
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
				ghidra_trace_connect('%s')
				ghidra_trace_start()
				ghidra_trace_txstart('Create Object')
				ghidra_trace_create_obj('Test.Objects[1]')
				print('---Lifespan---')
				ghidra_trace_insert_obj('Test.Objects[1]')
				print('---')
				ghidra_trace_txcommit()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/noname")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Test.Objects[1]"));
			assertNotNull(object);
			Lifespan life = Unique.assertOne(object.getLife().spans());
			assertEquals(Lifespan.nowOn(0), life);
			String expected = "Inserted object: lifespan=[0,+inf)";
			String actual = extractOutSection(out, "---Lifespan---");
			assertEquals(expected, actual.substring(0, expected.length()));
		}
	}

	@Test
	public void testRemoveObj() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create('notepad.exe')
				ghidra_trace_txstart('Create Object')
				ghidra_trace_create_obj('Test.Objects[1]')
				ghidra_trace_insert_obj('Test.Objects[1]')
				ghidra_trace_set_snap(1)
				ghidra_trace_remove_obj('Test.Objects[1]')
				ghidra_trace_txcommit()
				ghidra_trace_kill()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Test.Objects[1]"));
			assertNotNull(object);
			Lifespan life = Unique.assertOne(object.getLife().spans());
			assertEquals(Lifespan.at(0), life);
		}
	}

	@SuppressWarnings("unchecked")
	protected <T> T runTestSetValue(String extra, String pydbgExpr, String gtype)
			throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create('notepad.exe')
				ghidra_trace_txstart('Create Object')
				ghidra_trace_create_obj('Test.Objects[1]')
				ghidra_trace_insert_obj('Test.Objects[1]')
				%s
				ghidra_trace_set_value('Test.Objects[1]', 'test', %s, '%s')
				ghidra_trace_txcommit()
				ghidra_trace_kill()
				quit()
				""".formatted(PREAMBLE, addr, extra, pydbgExpr, gtype));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
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
		assertNull(runTestSetValue("", "None", "VOID"));
	}

	@Test
	public void testSetValueBool() throws Exception {
		assertEquals(Boolean.TRUE, runTestSetValue("", "True", "BOOL"));
	}

	@Test
	public void testSetValueByte() throws Exception {
		assertEquals(Byte.valueOf((byte) 1), runTestSetValue("", "'(char)1'", "BYTE"));
	}

	@Test
	public void testSetValueChar() throws Exception {
		assertEquals(Character.valueOf('A'), runTestSetValue("", "\"'A'\"", "CHAR"));
	}

	@Test
	public void testSetValueShort() throws Exception {
		assertEquals(Short.valueOf((short) 1), runTestSetValue("", "'(short)1'", "SHORT"));
	}

	@Test
	public void testSetValueInt() throws Exception {
		assertEquals(Integer.valueOf(1), runTestSetValue("", "'(int)1'", "INT"));
	}

	@Test
	public void testSetValueLong() throws Exception {
		assertEquals(Long.valueOf(1), runTestSetValue("", "'(long)1'", "LONG"));
	}

	@Test
	public void testSetValueString() throws Exception {
		assertEquals("HelloWorld!", runTestSetValue("", "\'HelloWorld!\'", "STRING"));
	}

	@Test //- how do we input long strings in python
	public void testSetValueStringWide() throws Exception {
		assertEquals("HelloWorld!", runTestSetValue("", "u\'HelloWorld!\'", "STRING"));
	}

	@Test
	public void testSetValueBoolArr() throws Exception {
		assertArrayEquals(new boolean[] { true, false },
			runTestSetValue("", "[True,False]", "BOOL_ARR"));
	}

	@Test
	public void testSetValueByteArrUsingString() throws Exception {
		assertArrayEquals(new byte[] { 'H', 1, 'W' },
			runTestSetValue("", "'H\\1W'", "BYTE_ARR"));
	}

	@Test
	public void testSetValueByteArrUsingArray() throws Exception {
		assertArrayEquals(new byte[] { 'H', 0, 'W' },
			runTestSetValue("", "['H',0,'W']", "BYTE_ARR"));
	}

	@Test
	public void testSetValueCharArrUsingString() throws Exception {
		assertArrayEquals(new char[] { 'H', 1, 'W' },
			runTestSetValue("", "'H\\1W'", "CHAR_ARR"));
	}

	@Test
	public void testSetValueCharArrUsingArray() throws Exception {
		assertArrayEquals(new char[] { 'H', 0, 'W' },
			runTestSetValue("", "['H',0,'W']", "CHAR_ARR"));
	}

	@Test
	public void testSetValueShortArrUsingString() throws Exception {
		assertArrayEquals(new short[] { 'H', 1, 'W' },
			runTestSetValue("", "'H\\1W'", "SHORT_ARR"));
	}

	@Test
	public void testSetValueShortArrUsingArray() throws Exception {
		assertArrayEquals(new short[] { 'H', 0, 'W' },
			runTestSetValue("", "['H',0,'W']", "SHORT_ARR"));
	}

	@Test
	public void testSetValueIntArrayUsingMixedArray() throws Exception {
		// Because explicit array type is chosen, we get null terminator
		assertArrayEquals(new int[] { 'H', 0, 'W' },
			runTestSetValue("", "['H',0,'W']", "INT_ARR"));
	}

	@Test
	public void testSetValueIntArrUsingArray() throws Exception {
		assertArrayEquals(new int[] { 1, 2, 3, 4 },
			runTestSetValue("", "[1,2,3,4]", "INT_ARR"));
	}

	@Test
	public void testSetValueLongArr() throws Exception {
		assertArrayEquals(new long[] { 1, 2, 3, 4 },
			runTestSetValue("", "[1,2,3,4]", "LONG_ARR"));
	}

	@Test
	public void testSetValueStringArr() throws Exception {
		assertArrayEquals(new String[] { "1", "A", "dead", "beef" },
			runTestSetValue("", "['1','A','dead','beef']", "STRING_ARR"));
	}

	@Test
	public void testSetValueAddress() throws Exception {
		Address address = runTestSetValue("", "'(void*)0xdeadbeef'", "ADDRESS");
		// Don't have the address factory to create expected address
		assertEquals(0xdeadbeefL, address.getOffset());
		assertEquals("ram", address.getAddressSpace().getName());
	}

	@Test
	public void testSetValueObject() throws Exception {
		TraceObject object = runTestSetValue("", "'Test.Objects[1]'", "OBJECT");
		assertEquals("Test.Objects[1]", object.getCanonicalPath().toString());
	}

	@Test
	public void testRetainValues() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create('notepad.exe')
				ghidra_trace_txstart('Create Object')
				ghidra_trace_create_obj('Test.Objects[1]')
				ghidra_trace_insert_obj('Test.Objects[1]')
				ghidra_trace_set_value('Test.Objects[1]', '[1]', '"A"', 'STRING')
				ghidra_trace_set_value('Test.Objects[1]', '[2]', '"B"', 'STRING')
				ghidra_trace_set_value('Test.Objects[1]', '[3]', '"C"', 'STRING')
				ghidra_trace_set_snap(10)
				ghidra_trace_retain_values('Test.Objects[1]', '[1] [3]')
				ghidra_trace_txcommit()
				ghidra_trace_kill()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
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
				ghidra_trace_connect('%s')
				ghidra_trace_start()
				ghidra_trace_txstart('Create Object')
				print('---Id---')
				ghidra_trace_create_obj('Test.Objects[1]')
				print('---')
				ghidra_trace_txcommit()
				print('---GetObject---')
				ghidra_trace_get_obj('Test.Objects[1]')
				print('---')
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/noname")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Test.Objects[1]"));
			assertNotNull(object);
			String expected = "1\tTest.Objects[1]";
			String actual = extractOutSection(out, "---GetObject---");
			assertEquals(expected, actual.substring(0, expected.length()));
		}
	}

	@Test
	public void testGetValues() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create('notepad.exe')
				ghidra_trace_txstart('Create Object')
				ghidra_trace_create_obj('Test.Objects[1]')
				ghidra_trace_insert_obj('Test.Objects[1]')
				ghidra_trace_set_value('Test.Objects[1]', 'vnull', None, 'VOID')
				ghidra_trace_set_value('Test.Objects[1]', 'vbool', True, 'BOOL')
				ghidra_trace_set_value('Test.Objects[1]', 'vbyte', '(char)1', 'BYTE')
				ghidra_trace_set_value('Test.Objects[1]', 'vchar', "'A'", 'CHAR')
				ghidra_trace_set_value('Test.Objects[1]', 'vshort', 2, 'SHORT')
				ghidra_trace_set_value('Test.Objects[1]', 'vint', 3, 'INT')
				ghidra_trace_set_value('Test.Objects[1]', 'vlong', 4, 'LONG')
				ghidra_trace_set_value('Test.Objects[1]', 'vstring', 'Hello', 'STRING')
				vboolarr = [True, False]
				ghidra_trace_set_value('Test.Objects[1]', 'vboolarr', vboolarr, 'BOOL_ARR')
				vbytearr = [1, 2, 3]
				ghidra_trace_set_value('Test.Objects[1]', 'vbytearr', vbytearr, 'BYTE_ARR')
				vchararr = 'Hello'
				ghidra_trace_set_value('Test.Objects[1]', 'vchararr', vchararr, 'CHAR_ARR')
				vshortarr = [1, 2, 3]
				ghidra_trace_set_value('Test.Objects[1]', 'vshortarr', vshortarr, 'SHORT_ARR')
				vintarr = [1, 2, 3]
				ghidra_trace_set_value('Test.Objects[1]', 'vintarr', vintarr, 'INT_ARR')
				vlongarr = [1, 2, 3]
				ghidra_trace_set_value('Test.Objects[1]', 'vlongarr', vlongarr, 'LONG_ARR')
				ghidra_trace_set_value('Test.Objects[1]', 'vaddr', '(void*)0xdeadbeef', 'ADDRESS')
				ghidra_trace_set_value('Test.Objects[1]', 'vobj', 'Test.Objects[1]', 'OBJECT')
				ghidra_trace_txcommit()
				print('---GetValues---')
				ghidra_trace_get_values('Test.Objects[1].')
				print('---')
				ghidra_trace_kill()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			String expected = """
					Parent          Key       Span     Value           Type
					Test.Objects[1] vbool     [0,+inf) True            BOOL
					Test.Objects[1] vboolarr  [0,+inf) [True, False]   BOOL_ARR
					Test.Objects[1] vbyte     [0,+inf) 1               BYTE
					Test.Objects[1] vbytearr  [0,+inf) b'\\x01\\x02\\x03' BYTE_ARR
					Test.Objects[1] vchar     [0,+inf) 'A'             CHAR
					Test.Objects[1] vchararr  [0,+inf) 'Hello'         CHAR_ARR
					Test.Objects[1] vint      [0,+inf) 3               INT
					Test.Objects[1] vintarr   [0,+inf) [1, 2, 3]       INT_ARR
					Test.Objects[1] vlong     [0,+inf) 4               LONG
					Test.Objects[1] vlongarr  [0,+inf) [1, 2, 3]       LONG_ARR
					Test.Objects[1] vobj      [0,+inf) Test.Objects[1] OBJECT
					Test.Objects[1] vshort    [0,+inf) 2               SHORT
					Test.Objects[1] vshortarr [0,+inf) [1, 2, 3]       SHORT_ARR
					Test.Objects[1] vstring   [0,+inf) 'Hello'         STRING
					Test.Objects[1] vaddr     [0,+inf) ram:deadbeef    ADDRESS"""
					.replaceAll(" ", "")
					.replaceAll("\n", "");
			String actual = extractOutSection(out, "---GetValues---").replaceAll(" ", "")
					.replaceAll("\r", "")
					.replaceAll("\n", "");
			assertEquals(
				expected,
				actual.substring(0, expected.length()));
		}
	}

	@Test
	public void testGetValuesRng() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create('notepad.exe')
				ghidra_trace_txstart('Create Object')
				ghidra_trace_create_obj('Test.Objects[1]')
				ghidra_trace_insert_obj('Test.Objects[1]')
				ghidra_trace_set_value('Test.Objects[1]', 'vaddr', '(void*)0xdeadbeef', 'ADDRESS')
				ghidra_trace_txcommit()
				print('---GetValues---')
				ghidra_trace_get_values_rng('(void*)0xdeadbeef 10')
				print('---')
				ghidra_trace_kill()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			String expected = """
					Parent          Key   Span     Value        Type

					Test.Objects[1] vaddr [0,+inf) ram:deadbeef ADDRESS""";
			String actual = extractOutSection(out, "---GetValues---").replaceAll("\r", "");
			assertEquals(expected, actual.substring(0, expected.length()));
		}
	}

	@Test
	public void testActivateObject() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create('notepad.exe')
				#set language c++
				ghidra_trace_txstart('Create Object')
				ghidra_trace_create_obj('Test.Objects[1]')
				ghidra_trace_insert_obj('Test.Objects[1]')
				ghidra_trace_txcommit()
				ghidra_trace_activate('Test.Objects[1]')
				ghidra_trace_kill()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
			assertSame(mdo.get(), traceManager.getCurrentTrace());
			assertEquals("Test.Objects[1]",
				traceManager.getCurrentObject().getCanonicalPath().toString());
		}
	}

	@Test
	public void testDisassemble() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create('notepad.exe')
				ghidra_trace_txstart('Tx')
				ghidra_trace_putmem('$pc 16')
				print('---Disassemble---')
				ghidra_trace_disassemble('$pc')
				print('---')
				ghidra_trace_txcommit()
				ghidra_trace_kill()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Not concerned about specifics, so long as disassembly occurs
			long total = 0;
			for (CodeUnit cu : tb.trace.getCodeManager().definedUnits().get(0, true)) {
				total += cu.getLength();
			}
			String extract = extractOutSection(out, "---Disassemble---");
			String[] split = extract.split("\r\n");
			assertEquals("Disassembled %d bytes".formatted(total),
				split[0]);
		}
	}

	@Test
	public void testPutProcesses() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_start()
				ghidra_trace_txstart('Tx')
				ghidra_trace_put_processes()
				ghidra_trace_txcommit()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/noname")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Would be nice to control / validate the specifics
			Collection<TraceObject> processes = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(0), PathPredicates.parse("Processes[]"))
					.map(p -> p.getDestination(null))
					.toList();
			assertEquals(0, processes.size());
		}
	}

	@Test
	public void testPutAvailable() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_start()
				ghidra_trace_txstart('Tx')
				ghidra_trace_put_available()
				ghidra_trace_txcommit()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/noname")) {
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
				ghidra_trace_connect('%s')
				ghidra_trace_create('notepad.exe')
				dbg = util.get_debugger()
				pc = dbg.reg.get_pc()
				dbg.bp(expr=pc)
				dbg.ba(expr=pc+4)
				ghidra_trace_txstart('Tx')
				ghidra_trace_put_breakpoints()
				ghidra_trace_txcommit()
				ghidra_trace_kill()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			List<TraceObjectValue> procBreakLocVals = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(0),
						PathPredicates.parse("Processes[].Breakpoints[]"))
					.map(p -> p.getLastEntry())
					.toList();
			assertEquals(2, procBreakLocVals.size());
			AddressRange rangeMain =
				procBreakLocVals.get(0).getChild().getValue(0, "_range").castValue();
			Address bp1 = rangeMain.getMinAddress();

			assertBreakLoc(procBreakLocVals.get(0), "[0]", bp1, 1,
				Set.of(TraceBreakpointKind.SW_EXECUTE),
				"ntdll!LdrInit");
			assertBreakLoc(procBreakLocVals.get(1), "[1]", bp1.add(4), 1,
				Set.of(TraceBreakpointKind.HW_EXECUTE),
				"ntdll!LdrInit");
		}
	}

	@Test
	public void testPutBreakpoints2() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create('notepad.exe')
				ghidra_trace_txstart('Tx')
				dbg = util.get_debugger()
				pc = dbg.reg.get_pc()
				dbg.ba(expr=pc, access=DbgEng.DEBUG_BREAK_EXECUTE)
				dbg.ba(expr=pc+4, access=DbgEng.DEBUG_BREAK_READ)
				dbg.ba(expr=pc+8, access=DbgEng.DEBUG_BREAK_WRITE)
				ghidra_trace_put_breakpoints()
				ghidra_trace_txcommit()
				ghidra_trace_kill()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			List<TraceObjectValue> procBreakVals = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(0),
						PathPredicates.parse("Processes[].Breakpoints[]"))
					.map(p -> p.getLastEntry())
					.toList();
			assertEquals(3, procBreakVals.size());
			AddressRange rangeMain0 =
				procBreakVals.get(0).getChild().getValue(0, "_range").castValue();
			Address main0 = rangeMain0.getMinAddress();
			AddressRange rangeMain1 =
				procBreakVals.get(1).getChild().getValue(0, "_range").castValue();
			Address main1 = rangeMain1.getMinAddress();
			AddressRange rangeMain2 =
				procBreakVals.get(2).getChild().getValue(0, "_range").castValue();
			Address main2 = rangeMain2.getMinAddress();

			assertWatchLoc(procBreakVals.get(0), "[0]", main0, (int) rangeMain0.getLength(),
				Set.of(TraceBreakpointKind.HW_EXECUTE), "ntdll!LdrInit");
			assertWatchLoc(procBreakVals.get(1), "[1]", main1, (int) rangeMain1.getLength(),
				Set.of(TraceBreakpointKind.WRITE), "ntdll!LdrInit");
			assertWatchLoc(procBreakVals.get(2), "[2]", main2, (int) rangeMain2.getLength(),
				Set.of(TraceBreakpointKind.READ), "ntdll!LdrInit");
		}
	}

	@Test
	public void testPutEnvironment() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create('notepad.exe')
				ghidra_trace_txstart('Tx')
				ghidra_trace_put_environment()
				ghidra_trace_txcommit()
				ghidra_trace_kill()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Assumes LLDB on Linux amd64
			TraceObject env =
				Objects.requireNonNull(tb.objAny("Processes[].Environment", Lifespan.at(0)));
			assertEquals("pydbg", env.getValue(0, "_debugger").getValue());
			assertEquals("x86_64", env.getValue(0, "_arch").getValue());
			assertEquals("windows", env.getValue(0, "_os").getValue());
			assertEquals("little", env.getValue(0, "_endian").getValue());
		}
	}

	@Test
	public void testPutRegions() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create('notepad.exe')
				ghidra_trace_txstart('Tx')
				ghidra_trace_put_regions()
				ghidra_trace_txcommit()
				ghidra_trace_kill()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
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
				ghidra_trace_connect('%s')
				ghidra_trace_create('notepad.exe')
				ghidra_trace_txstart('Tx')
				ghidra_trace_put_modules()
				ghidra_trace_txcommit()
				ghidra_trace_kill()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Would be nice to control / validate the specifics
			Collection<? extends TraceModule> all = tb.trace.getModuleManager().getAllModules();
			TraceModule modBash =
				Unique.assertOne(all.stream().filter(m -> m.getName().contains("notepad")));
			assertNotEquals(tb.addr(0), Objects.requireNonNull(modBash.getBase()));
		}
	}

	@Test
	public void testPutThreads() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create('notepad.exe')
				ghidra_trace_txstart('Tx')
				ghidra_trace_put_threads()
				ghidra_trace_txcommit()
				ghidra_trace_kill()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Would be nice to control / validate the specifics
			Collection<? extends TraceThread> threads = tb.trace.getThreadManager().getAllThreads();
			assertThat(threads.size(), greaterThan(2));
		}
	}

	@Test
	public void testPutFrames() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create('notepad.exe')
				ghidra_trace_txstart('Tx')
				ghidra_trace_put_frames()
				ghidra_trace_txcommit()
				ghidra_trace_kill()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/pydbg/notepad.exe")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Would be nice to control / validate the specifics
			List<TraceObject> stack = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(0),
						PathPredicates.parse("Processes[0].Threads[0].Stack[]"))
					.map(p -> p.getDestination(null))
					.toList();
			assertThat(stack.size(), greaterThan(2));
		}
	}

	@Test
	public void testMinimal() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				print('FINISHED')
				quit()
				""".formatted(PREAMBLE, addr));
	}

	@Test
	public void testMinimal2() throws Exception {
		Function<String, String> scriptSupplier = addr -> """
				%s
				ghidra_trace_connect('%s')
				""".formatted(PREAMBLE, addr);
		try (PythonAndConnection conn = startAndConnectPython(scriptSupplier)) {
			conn.execute("print('FINISHED')");
			conn.close();
		}
	}
}
