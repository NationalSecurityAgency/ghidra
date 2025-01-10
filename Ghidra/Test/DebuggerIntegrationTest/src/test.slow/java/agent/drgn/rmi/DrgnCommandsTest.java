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
package agent.drgn.rmi;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.junit.Test;

import db.Transaction;
import generic.Unique;
import ghidra.app.plugin.core.debug.utils.ManagedDomainObject;
import ghidra.debug.api.tracermi.TraceRmiAcceptor;
import ghidra.debug.api.tracermi.TraceRmiConnection;
import ghidra.framework.Application;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.Float10DataType;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.CodeUnit;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.listing.TraceCodeSpace;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.path.PathFilter;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.Msg;

public class DrgnCommandsTest extends AbstractDrgnTraceRmiTest {
	
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
					from ghidradrgn.commands import *
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
				ghidra_trace_create()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject(MDO)) {
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
				ghidra_trace_connect('%s')
				ghidra_trace_start()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/drgn/noname")) {
			assertThat(mdo.get(), instanceOf(Trace.class));
		}
	}

	@Test
	public void testStartTraceCustomize() throws Exception {
		runThrowError(
			addr -> """
					%s
					ghidra_trace_connect('%s')
					ghidra_trace_create(start_trace=False)
					util.set_convenience_variable('ghidra-language','Toy:BE:64:default')
					util.set_convenience_variable('ghidra-compiler','default')
					ghidra_trace_start('myToy')
					quit()
					"""
					.formatted(PREAMBLE, addr));
		DomainFile df = env.getProject().getProjectData().getFile("/New Traces/myToy");
		assertNotNull(df);
		try (ManagedDomainObject mdo = new ManagedDomainObject(df, false, false, monitor)) {
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
				ghidra_trace_connect('%s')
				ghidra_trace_create()
				ghidra_trace_stop()
				quit()
				""".formatted(PREAMBLE, addr));
		DomainFile df =
			env.getProject().getProjectData().getFile(MDO);
		assertNotNull(df);
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
					print('---BeforeConnect---')
					ghidra_trace_connect('%s')
					print('---Connect---')
					ghidra_trace_info()
					print('---Create---')
					ghidra_trace_create()
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
				Connected to %s %s at %s
				No trace""".formatted(
			Application.getName(), Application.getApplicationVersion(), refAddr.get()),
			extractOutSection(out, "---Connect---").replaceAll("\r", ""));
		assertEquals("""
				Connected to %s %s at %s
				Trace active""".formatted(
			Application.getName(), Application.getApplicationVersion(), refAddr.get()),
			extractOutSection(out, "---Start---").replaceAll("\r", ""));
		assertEquals("""
				Connected to %s %s at %s
				No trace""".formatted(
			Application.getName(), Application.getApplicationVersion(), refAddr.get()),
			extractOutSection(out, "---Stop---").replaceAll("\r", ""));
		assertEquals("""
				Not connected to Ghidra""",
			extractOutSection(out, "---Disconnect---"));
	}

	@Test 
	public void testLcsp() throws Exception {
		String out = runThrowError(addr ->
					"""
					%s
					ghidra_trace_connect('%s')
					print('---Import---')
					ghidra_trace_info_lcsp()
					print('---Create---')
					ghidra_trace_create()
					print('---File---')
					ghidra_trace_info_lcsp()
					util.set_convenience_variable('ghidra-language','DATA:BE:64:default')
					print('---Language---')
					ghidra_trace_info_lcsp()
					util.set_convenience_variable('ghidra-compiler','posStack')
					print('---Compiler---')
					ghidra_trace_info_lcsp()
					quit()
					""".formatted(PREAMBLE, addr));

		assertEquals("""
				Selected Ghidra language: x86:LE:64:default
				Selected Ghidra compiler: gcc""",
			extractOutSection(out, "---File---").replaceAll("\r", ""));
		assertEquals("""
				Using the DATA64 compiler map
				Selected Ghidra language: DATA:BE:64:default
				Selected Ghidra compiler: pointer64""",
			extractOutSection(out, "---Language---").replaceAll("\r", ""));
		assertEquals("""
				Selected Ghidra language: DATA:BE:64:default
				Selected Ghidra compiler: posStack""",
			extractOutSection(out, "---Compiler---").replaceAll("\r", ""));
	}

	@Test
	public void testSnapshot() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create()
				ghidra_trace_txstart('Create snapshot')
				ghidra_trace_new_snap('Scripted snapshot')
				ghidra_trace_txcommit()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject(MDO)) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceSnapshot snapshot = Unique.assertOne(tb.trace.getTimeManager().getAllSnapshots());
			assertEquals(0, snapshot.getKey());
			assertEquals("Scripted snapshot", snapshot.getDescription());
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
				ghidra_trace_create()
				ghidra_trace_txstart('Create snapshot')
				ghidra_trace_new_snap('Scripted snapshot')
				ghidra_trace_putreg()
				ghidra_trace_txcommit()
				quit()
				""".formatted(PREAMBLE, addr, count));
		try (ManagedDomainObject mdo = openDomainObject(MDO)) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = Unique.assertOne(tb.trace.getTimeManager().getAllSnapshots()).getKey();
			List<TraceObjectValue> regVals = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(0),
						PathFilter.parse("Processes[].Threads[].Stack[].Registers"))
					.map(p -> p.getLastEntry())
					.toList();
			TraceObjectValue tobj = regVals.get(0);
			AddressSpace t1f0 = tb.trace.getBaseAddressFactory()
					.getAddressSpace(tobj.getCanonicalPath().toString());
			TraceMemorySpace regs = tb.trace.getMemoryManager().getMemorySpace(t1f0, false);

			RegisterValue rip = regs.getValue(snap, tb.reg("rip"));
			assertEquals("3a40cdf7ff7f0000", rip.getUnsignedValue().toString(16));

			try (Transaction tx = tb.trace.openTransaction("Float80 unit")) {
				TraceCodeSpace code = tb.trace.getCodeManager().getCodeSpace(t1f0, true);
				code.definedData()
						.create(Lifespan.nowOn(0), tb.reg("st0"), Float10DataType.dataType);
			}
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
				ghidra_trace_create()
				ghidra_trace_txstart('Create snapshot')
				ghidra_trace_new_snap('Scripted snapshot')
				ghidra_trace_putreg()
				ghidra_trace_delreg()
				ghidra_trace_txcommit()
				quit()
				""".formatted(PREAMBLE, addr, count));
		// The spaces will be left over, but the values should be zeroed
		try (ManagedDomainObject mdo = openDomainObject(MDO)) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = Unique.assertOne(tb.trace.getTimeManager().getAllSnapshots()).getKey();
			List<TraceObjectValue> regVals = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(0),
						PathFilter.parse("Processes[].Threads[].Stack[].Registers"))
					.map(p -> p.getLastEntry())
					.toList();
			TraceObjectValue tobj = regVals.get(0);
			AddressSpace t1f0 = tb.trace.getBaseAddressFactory()
					.getAddressSpace(tobj.getCanonicalPath().toString());
			TraceMemorySpace regs = tb.trace.getMemoryManager().getMemorySpace(t1f0, false);

			RegisterValue rax = regs.getValue(snap, tb.reg("rax"));
			assertEquals("0", rax.getUnsignedValue().toString(16));
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
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/drgn/noname")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(KeyPath.parse("Test.Objects[1]"));
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
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/drgn/noname")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(KeyPath.parse("Test.Objects[1]"));
			assertNotNull(object);
			Lifespan life = Unique.assertOne(object.getLife().spans());
			assertEquals(Lifespan.nowOn(0), life);
			assertEquals("Inserted object: lifespan=[0,+inf)",
				extractOutSection(out, "---Lifespan---"));
		}
	}

	@Test
	public void testRemoveObj() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create()
				ghidra_trace_txstart('Create Object')
				ghidra_trace_create_obj('Test.Objects[1]')
				ghidra_trace_insert_obj('Test.Objects[1]')
				ghidra_trace_set_snap(1)
				ghidra_trace_remove_obj('Test.Objects[1]')
				ghidra_trace_txcommit()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject(MDO)) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(KeyPath.parse("Test.Objects[1]"));
			assertNotNull(object);
			Lifespan life = Unique.assertOne(object.getLife().spans());
			assertEquals(Lifespan.at(0), life);
		}
	}

	@SuppressWarnings("unchecked")
	protected <T> T runTestSetValue(String extra, String drgnExpr, String gtype)
			throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create()
				ghidra_trace_txstart('Create Object')
				ghidra_trace_create_obj('Test.Objects[1]')
				ghidra_trace_insert_obj('Test.Objects[1]')
				%s
				ghidra_trace_set_value('Test.Objects[1]', 'test', %s, '%s')
				ghidra_trace_txcommit()
				quit()
				""".formatted(PREAMBLE, addr, extra, drgnExpr, gtype));
		try (ManagedDomainObject mdo = openDomainObject(MDO)) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(KeyPath.parse("Test.Objects[1]"));
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
		assertEquals(Byte.valueOf((byte) 1), runTestSetValue("", "'1'", "BYTE"));
	}

	@Test
	public void testSetValueChar() throws Exception {
		assertEquals(Character.valueOf('A'), runTestSetValue("", "'A'", "CHAR"));
	}

	@Test
	public void testSetValueShort() throws Exception {
		assertEquals(Short.valueOf((short) 1), runTestSetValue("", "'1'", "SHORT"));
	}

	@Test
	public void testSetValueInt() throws Exception {
		assertEquals(Integer.valueOf(1), runTestSetValue("", "'1'", "INT"));
	}

	@Test
	public void testSetValueLong() throws Exception {
		assertEquals(Long.valueOf(1), runTestSetValue("", "'1'", "LONG"));
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
		Address address = runTestSetValue("", "0xdeadbeef", "ADDRESS");
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
				ghidra_trace_create()
				ghidra_trace_txstart('Create Object')
				ghidra_trace_create_obj('Test.Objects[1]')
				ghidra_trace_insert_obj('Test.Objects[1]')
				ghidra_trace_set_value('Test.Objects[1]', '[1]', '"A"', 'STRING')
				ghidra_trace_set_value('Test.Objects[1]', '[2]', '"B"', 'STRING')
				ghidra_trace_set_value('Test.Objects[1]', '[3]', '"C"', 'STRING')
				ghidra_trace_set_snap(10)
				ghidra_trace_retain_values('Test.Objects[1]', '[1] [3]')
				ghidra_trace_txcommit()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject(MDO)) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(KeyPath.parse("Test.Objects[1]"));
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
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/drgn/noname")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(KeyPath.parse("Test.Objects[1]"));
			assertNotNull(object);
			assertEquals("1\tTest.Objects[1]", extractOutSection(out, "---GetObject---"));
		}
	}

	@Test
	public void testGetValues() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create()
				ghidra_trace_txstart('Create Object')
				ghidra_trace_create_obj('Test.Objects[1]')
				ghidra_trace_insert_obj('Test.Objects[1]')
				ghidra_trace_set_value('Test.Objects[1]', 'vnull', None, 'VOID')
				ghidra_trace_set_value('Test.Objects[1]', 'vbool', True, 'BOOL')
				ghidra_trace_set_value('Test.Objects[1]', 'vbyte', '1', 'BYTE')
				ghidra_trace_set_value('Test.Objects[1]', 'vchar', 'A', 'CHAR')
				ghidra_trace_set_value('Test.Objects[1]', 'vshort', '2', 'SHORT')
				ghidra_trace_set_value('Test.Objects[1]', 'vint', '3', 'INT')
				ghidra_trace_set_value('Test.Objects[1]', 'vlong', '4', 'LONG')
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
				ghidra_trace_set_value('Test.Objects[1]', 'vaddr', 0xdeadbeef, 'ADDRESS')
				ghidra_trace_set_value('Test.Objects[1]', 'vobj', 'Test.Objects[1]', 'OBJECT')
				ghidra_trace_txcommit()
				print('---GetValues---')
				ghidra_trace_get_values('Test.Objects[1].')
				print('---')
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject(MDO)) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			assertEquals("""
					Parent          Key       Span     Value           Type
					Test.Objects[1] vaddr     [0,+inf) ram:deadbeef    ADDRESS
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
					Test.Objects[1] vstring   [0,+inf) 'Hello'         STRING""",
				extractOutSection(out, "---GetValues---").replaceAll("\r", ""));
		}
	}

	@Test
	public void testGetValuesRng() throws Exception {
		String out = runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create()
				ghidra_trace_txstart('Create Object')
				ghidra_trace_create_obj('Test.Objects[1]')
				ghidra_trace_insert_obj('Test.Objects[1]')
				ghidra_trace_set_value('Test.Objects[1]', 'vaddr', 0xdeadbeef, 'ADDRESS')
				ghidra_trace_txcommit()
				print('---GetValues---')
				ghidra_trace_get_values_rng(0xdeadbeef, 10)
				print('---')
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject(MDO)) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			assertEquals("""
					Parent          Key   Span     Value        Type
					Test.Objects[1] vaddr [0,+inf) ram:deadbeef ADDRESS""",
				extractOutSection(out, "---GetValues---").replaceAll("\r", ""));
		}
	}

	@Test
	public void testActivateObject() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create()
				#set language c++
				ghidra_trace_txstart('Create Object')
				ghidra_trace_create_obj('Test.Objects[1]')
				ghidra_trace_insert_obj('Test.Objects[1]')
				ghidra_trace_txcommit()
				ghidra_trace_activate('Test.Objects[1]')
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject(MDO)) {
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
				ghidra_trace_create()
				ghidra_trace_txstart('Tx')
				pc = get_pc()
				ghidra_trace_putmem(pc, 16)
				print('---Disassemble---')
				ghidra_trace_disassemble(pc)
				print('---')
				ghidra_trace_txcommit()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject(MDO)) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Not concerned about specifics, so long as disassembly occurs
			long total = 0;
			for (CodeUnit cu : tb.trace.getCodeManager().definedUnits().get(0, true)) {
				total += cu.getLength();
			}
			String extract = extractOutSection(out, "---Disassemble---");
			String[] split = extract.split("\r\n");
			// NB: core.12137 has no memory
			//assertEquals("Disassembled %d bytes".formatted(total),
			//	split[0]);
			assertEquals(0, total);
			assertEquals("", split[0]);
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
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/drgn/noname")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Would be nice to control / validate the specifics
			Collection<TraceObject> processes = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(0), PathFilter.parse("Processes[]"))
					.map(p -> p.getDestination(null))
					.toList();
			assertEquals(0, processes.size());
		}
	}

	@Test
	public void testPutEnvironment() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create()
				ghidra_trace_txstart('Tx')
				ghidra_trace_put_environment()
				ghidra_trace_txcommit()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject(MDO)) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Assumes LLDB on Linux amd64
			TraceObject envobj =
				Objects.requireNonNull(tb.objAny("Processes[].Environment", Lifespan.at(0)));
			assertEquals("drgn", envobj.getValue(0, "_debugger").getValue());
			assertEquals("X86_64", envobj.getValue(0, "_arch").getValue());
			assertEquals("Language.C", envobj.getValue(0, "_os").getValue());
			assertEquals("little", envobj.getValue(0, "_endian").getValue());
		}
	}

	@Test
	public void testPutRegions() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create()
				ghidra_trace_txstart('Tx')
				ghidra_trace_put_regions()
				ghidra_trace_txcommit()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject(MDO)) {
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
				ghidra_trace_create()
				ghidra_trace_txstart('Tx')
				ghidra_trace_put_modules()
				ghidra_trace_txcommit()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject(MDO)) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Would be nice to control / validate the specifics
			Collection<? extends TraceModule> all = tb.trace.getModuleManager().getAllModules();
			TraceModule modBash =
				Unique.assertOne(all.stream().filter(m -> m.getName().contains("helloWorld")));
			assertNotEquals(tb.addr(0), Objects.requireNonNull(modBash.getBase()));
		}
	}

	@Test
	public void testPutThreads() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create()
				ghidra_trace_txstart('Tx')
				ghidra_trace_put_threads()
				ghidra_trace_txcommit()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject(MDO)) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Would be nice to control / validate the specifics
			Collection<? extends TraceThread> threads = tb.trace.getThreadManager().getAllThreads();
			assertEquals(1, threads.size());
		}
	}

	@Test
	public void testPutFrames() throws Exception {
		runThrowError(addr -> """
				%s
				ghidra_trace_connect('%s')
				ghidra_trace_create()
				ghidra_trace_txstart('Tx')
				ghidra_trace_put_frames()
				ghidra_trace_txcommit()
				quit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject(MDO)) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			// Would be nice to control / validate the specifics
			List<TraceObject> stack = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(0),
						PathFilter.parse("Processes[0].Threads[].Stack[]"))
					.map(p -> p.getDestination(null))
					.toList();
			assertEquals(7, stack.size());
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

}
