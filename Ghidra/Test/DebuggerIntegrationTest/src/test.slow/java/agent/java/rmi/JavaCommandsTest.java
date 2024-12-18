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
package agent.java.rmi;

import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import org.junit.Ignore;
import org.junit.Test;

import generic.Unique;
import ghidra.app.plugin.core.debug.utils.ManagedDomainObject;
import ghidra.dbg.util.PathPredicates;
import ghidra.debug.api.tracermi.TraceRmiAcceptor;
import ghidra.debug.api.tracermi.TraceRmiConnection;
import ghidra.framework.model.DomainFile;
import ghidra.lifecycle.Unfinished;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.CodeUnit;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.*;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.target.*;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.Msg;

@Ignore
public class JavaCommandsTest extends AbstractJavaTraceRmiTest {

	public static final String HWSETUP = """
			cmds.ghidraTraceStart("HelloWorld.class");
			cmds.ghidraTraceCreate(System.getenv());
			cmds.ghidraTraceTxStart("Create snapshot");
			cmds.ghidraTraceNewSnap("Scripted snapshot");
			""";

	public static final String HWSETUP_W_STATE =
		"""
				cmds.ghidraTraceStart("HelloWorld.class");
				cmds.ghidraTraceCreate(System.getenv());
				// No state yet
				ThreadReference thread = manager.getCurrentThread();
				VirtualMachine vm = manager.getCurrentVM();
				StepRequest stepReq = vm.eventRequestManager().createStepRequest(thread, StepRequest.STEP_MIN, StepRequest.STEP_INTO);
				stepReq.enable();
				vm.resume();
				cmds.ghidraTraceTxStart("Create snapshot");
				cmds.ghidraTraceNewSnap("Scripted snapshot");
				Location loc = manager.getCurrentLocation();
				Address pc = jdiManager.getAddressFromLocation(loc);
				""";

	public static final String TESTSETUP = """
			cmds.ghidraTraceStart("Test");
			cmds.ghidraTraceTxStart("Create Object")
			cmds.ghidraTraceNewSnap("Scripted snapshot");
			System.err.println("Created snapshot");
			cmds.ghidraTraceCreateObj("Test.Objects[1]");
			cmds.ghidraTraceInsertObj("Test.Objects[1]");
			""";

	//@Test
	public void testManual() throws Exception {
		TraceRmiAcceptor acceptor = traceRmi.acceptOne(null);
		Msg.info(this,
			"Use: cmds.ghidraTraceConnect(" + sockToStringForJshell(acceptor.getAddress()) + ")");
		TraceRmiConnection connection = acceptor.accept();
		Msg.info(this, "Connected: " + sockToStringForJshell(connection.getRemoteAddress()));
		connection.waitClosed();
		Msg.info(this, "Closed");
	}

	@Test
	public void testConnect() throws Exception {
		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				/exit
				""".formatted(PREAMBLE, addr));
	}

	@Test
	public void testDisconnect() throws Exception {
		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				cmds.ghidraTraceDisconnect();
				/exit
				""".formatted(PREAMBLE, addr));
	}

	@Test
	public void testStartTraceDefaults() throws Exception {
		// Default name and lcsp
		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				cmds.ghidraTraceStart("HelloWorld.class");
				/exit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			assertEquals("JVM:BE:32:default",
				tb.trace.getBaseLanguage().getLanguageID().getIdAsString());
			assertEquals("default",
				tb.trace.getBaseCompilerSpec().getCompilerSpecID().getIdAsString());
		}
	}

	@Test
	public void testStartTraceDefaultNoFile() throws Exception {
		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				cmds.ghidraTraceStart(null);
				/exit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/jdi/noname")) {
			assertThat(mdo.get(), instanceOf(Trace.class));
		}
	}

	@Test
	public void testStopTrace() throws Exception {
		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				cmds.ghidraTraceCreate(System.getenv());
				cmds.ghidraTraceStart("HelloWorld.class");
				cmds.ghidraTraceStop();
				cmds.ghidraTraceSave();
				/exit
				""".formatted(PREAMBLE, addr));
		DomainFile dfMyToy =
			env.getProject().getProjectData().getFile("/New Traces/HelloWorld.class");
		assertNotNull(dfMyToy);
		assertFalse(dfMyToy.isOpen());
	}

	@Test
	public void testInfo() throws Exception {
		AtomicReference<String> refAddr = new AtomicReference<>();
		String out = runThrowError(addr -> {
			refAddr.set(addr);
			return """
					%s
					System.out.println("---Import---");
					cmds.ghidraTraceInfo();
					System.out.println("---BeforeConnect---");
					cmds.ghidraTraceConnect("%s");
					System.out.println("---Connect---");
					cmds.ghidraTraceInfo();
					System.out.println("---Create---");
					cmds.ghidraTraceStart("HelloWorld.class");
					cmds.ghidraTraceCreate(System.getenv());
					System.out.println("---Start---");
					cmds.ghidraTraceInfo();
					cmds.ghidraTraceStop();
					System.out.println("---Stop---");
					cmds.ghidraTraceInfo();
					cmds.ghidraTraceDisconnect();
					System.out.println("---Disconnect---");
					cmds.ghidraTraceInfo();
					/exit
					""".formatted(PREAMBLE, addr);
		});

		assertEquals("""
				ERROR Not connected to Ghidra""",
			extractOutSection(out, "---Import---"));
		assertEquals("""
				INFO  Connected to jdi at /%s
				ERROR No trace""".formatted(refAddr.get()),
			extractOutSection(out, "---Connect---").replaceAll("\r", ""));
		assertEquals("""
				INFO  Connected to jdi at /%s
				INFO  Trace active""".formatted(refAddr.get()),
			extractOutSection(out, "---Start---").replaceAll("\r", ""));
		assertEquals("""
				ERROR Not connected to Ghidra\n|  Goodbye""",
			extractOutSection(out, "---Disconnect---"));
	}

	@Test
	public void testLcsp() throws Exception {
		String out = runThrowError(
			"""
					%s
					System.out.println("---Import---");
					cmds.ghidraTraceInfoLcsp();
					System.out.println("---Create---");
					cmds.ghidraTraceCreate(System.getenv());
					System.out.println("---File---");
					cmds.ghidraTraceInfoLcsp();
					/exit
					""".formatted(PREAMBLE));

		assertEquals("""
				INFO  Selected Ghidra language: JVM:BE:32:default
				INFO  Selected Ghidra compiler: default
				|  Goodbye""",
			extractOutSection(out, "---File---").replaceAll("\r", ""));
	}

	@Test
	public void testSave() throws Exception {
		traceManager.setSaveTracesByDefault(false);

		// For sanity check, verify failing to save drops data
		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				cmds.ghidraTraceTxCommit();
				cmds.ghidraTraceStop();
				cmds.ghidraTraceDisconnect();
				/exit
				""".formatted(PREAMBLE, addr, HWSETUP));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			assertEquals(0, tb.trace.getTimeManager().getAllSnapshots().size());
		}
		finally {
			tb.close();

			DomainFile df =
				env.getProject().getProjectData().getFile("/New Traces/HelloWorld.class");
			waitForCondition(() -> !df.isOpen());
			df.delete();
		}

		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				cmds.ghidraTraceTxCommit();
				cmds.ghidraTraceSave();
				cmds.ghidraTraceStop();
				cmds.ghidraTraceDisconnect();
				/exit
				""".formatted(PREAMBLE, addr, HWSETUP));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			assertNotEquals(0, tb.trace.getTimeManager().getAllSnapshots().size());
		}
	}

	@Test
	public void testSnapshot() throws Exception {
		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				cmds.ghidraTraceTxCommit();
				cmds.ghidraTraceSave();
				/exit
				""".formatted(PREAMBLE, addr, HWSETUP));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			assertEquals(2, tb.trace.getTimeManager().getAllSnapshots().size());
			TraceSnapshot snapshot = getLastSnapshot();
			assertEquals(1, snapshot.getKey());
			assertEquals("Scripted snapshot", snapshot.getDescription());
		}
	}

	@Test
	public void testPutMem() throws Exception {
		String out = runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				cmds.ghidraTracePutMem(pc, 16);
				cmds.ghidraTraceTxCommit();
				Method method = jdiManager.getMethodForAddress(pc);
				System.out.println("---Dump---");
				byte[] bytecodes = method.bytecodes();
				System.out.println(pc);
				System.out.println("---");
				cmds.ghidraTraceSave();
				cmds.ghidraTraceDisconnect();
				/exit
				""".formatted(PREAMBLE, addr, HWSETUP_W_STATE));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = getLastSnapshot().getKey();
			MemDump dump = parseHexDump(extractOutSection(out, "---Dump---"));
			ByteBuffer buf = ByteBuffer.allocate(dump.data().length);
			tb.trace.getMemoryManager().getBytes(snap, tb.addr(dump.address()), buf);

			assertArrayEquals(dump.data(), buf.array());
		}
	}

	@Test
	public void testPutMemState() throws Exception {
		String out = runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				cmds.ghidraTracePutMemState(pc, 16, MemoryState.MS_KNOWN);
				cmds.ghidraTraceTxCommit();
				Method method = jdiManager.getMethodForAddress(pc);
				System.out.println("---Start---");
				byte[] bytecodes = method.bytecodes();
				System.out.println(pc);
				System.out.println("---");
				cmds.ghidraTraceSave();
				cmds.ghidraTraceDisconnect();
				/exit
				""".formatted(PREAMBLE, addr, HWSETUP_W_STATE));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = getLastSnapshot().getKey();
			String eval = extractOutSection(out, "---Start---");
			List<String> lines = List.of(eval.split("\n"));
			Address addr = tb.addr(Long.parseLong(lines.get(1), 16));

			Entry<TraceAddressSnapRange, TraceMemoryState> entry =
				tb.trace.getMemoryManager().getMostRecentStateEntry(snap, addr);
			assertEquals(Map.entry(new ImmutableTraceAddressSnapRange(
				rng(addr, 16), Lifespan.at(2)), TraceMemoryState.KNOWN), entry);
		}
	}

	@Test
	public void testDelMem() throws Exception {
		String out = runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				cmds.ghidraTraceSetSnap(1);
				cmds.ghidraTraceDelMem(pc, 8);
				cmds.ghidraTraceTxCommit();
				Method method = jdiManager.getMethodForAddress(pc);
				System.out.println("---Dump---");
				byte[] bytecodes = method.bytecodes();
				System.out.println(pc);
				System.out.println("---");
				cmds.ghidraTraceSave();
				cmds.ghidraTraceDisconnect();
				/exit
				""".formatted(PREAMBLE, addr, HWSETUP_W_STATE));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = getLastSnapshot().getKey();
			MemDump dump = parseHexDump(extractOutSection(out, "---Dump---"));
			Arrays.fill(dump.data(), 0, 8, (byte) 0);
			ByteBuffer buf = ByteBuffer.allocate(dump.data().length);
			tb.trace.getMemoryManager().getBytes(snap, tb.addr(dump.address()), buf);
			assertArrayEquals(dump.data(), buf.array());
		}
	}

	@Test
	public void testPutReg() throws Exception {
		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				StackFrame frame = manager.getCurrentFrame();
				cmds.ghidraTracePutReg(frame);
				cmds.ghidraTraceTxCommit();
				cmds.ghidraTraceSave();
				cmds.ghidraTraceDisconnect();
				/exit
				""".formatted(PREAMBLE, addr, HWSETUP_W_STATE));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = getLastSnapshot().getKey();
			List<TraceObjectValue> regVals = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(snap),
						PathPredicates.parse("VMs[].Threads[main].Stack[0].Registers"))
					.map(p -> p.getLastEntry())
					.toList();
			TraceObjectValue tobj = regVals.get(0);
			AddressSpace t1f0 = tb.trace.getBaseAddressFactory()
					.getAddressSpace(tobj.getCanonicalPath().toString());
			TraceMemorySpace regs = tb.trace.getMemoryManager().getMemorySpace(t1f0, false);

			RegisterValue pc = regs.getValue(snap, tb.reg("PC"));
			assertEquals("1451", pc.getUnsignedValue().toString(16));
		}
	}

	@Test
	public void testDelReg() throws Exception {
		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				cmds.ghidraTraceSetSnap(1);
				StackFrame frame = manager.getCurrentFrame();
				cmds.ghidraTraceDelReg(frame);
				cmds.ghidraTraceTxCommit();
				cmds.ghidraTraceSave();
				cmds.ghidraTraceDisconnect();
				/exit
				""".formatted(PREAMBLE, addr, HWSETUP_W_STATE));
		// The spaces will be left over, but the values should be zeroed
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = getLastSnapshot().getKey();
			List<TraceObjectValue> regVals = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(snap),
						PathPredicates.parse("VMs[].Threads[main].Stack[0].Registers"))
					.map(p -> p.getLastEntry())
					.toList();
			TraceObjectValue tobj = regVals.get(0);
			AddressSpace t1f0 = tb.trace.getBaseAddressFactory()
					.getAddressSpace(tobj.getCanonicalPath().toString());
			TraceMemorySpace regs = tb.trace.getMemoryManager().getMemorySpace(t1f0, false);

			RegisterValue pc = regs.getValue(snap, tb.reg("PC"));
			assertEquals("0", pc.getUnsignedValue().toString(16));
		}
	}

	@Test
	public void testCreateObj() throws Exception {
		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				cmds.ghidraTraceCreateObj("Test.Objects[1].Bob")
				cmds.ghidraTraceTxCommit()
				cmds.ghidraTraceSave();
				/exit
				""".formatted(PREAMBLE, addr, TESTSETUP));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/Test")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Test.Objects[1].Bob"));
			assertNotNull(object);
			assertEquals(4L, object.getKey());
		}
	}

	@Test
	public void testInsertObj() throws Exception {
		String out = runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				System.out.println("---Lifespan---");
				cmds.ghidraTraceCreateObj("Test.Objects[1].Bob")
				cmds.ghidraTraceInsertObj("Test.Objects[1].Bob")
				System.out.println("---");
				cmds.ghidraTraceTxCommit()
				cmds.ghidraTraceSave();
				/exit
				""".formatted(PREAMBLE, addr, TESTSETUP));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/Test")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Test.Objects[1].Bob"));
			assertNotNull(object);
			Lifespan life = Unique.assertOne(object.getLife().spans());
			assertEquals(Lifespan.nowOn(0), life);
			assertEquals("Inserted object: lifespan=[0..+inf)",
				extractOutSection(out, "---Lifespan---"));
		}
	}

	@Test
	public void testRemoveObj() throws Exception {
		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				cmds.ghidraTraceInsertObj("Test.Objects[1]")
				cmds.ghidraTraceSetSnap(2);
				cmds.ghidraTraceRemoveObj("Test.Objects[1]");
				cmds.ghidraTraceTxCommit();
				cmds.ghidraTraceSave();
				cmds.ghidraTraceDisconnect();
				/exit
				""".formatted(PREAMBLE, addr, TESTSETUP));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/Test")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Test.Objects[1]"));
			assertNotNull(object);
			Lifespan life = Unique.assertOne(object.getLife().spans());
			assertEquals(Lifespan.span(0, 1), life);
		}
	}

	@SuppressWarnings("unchecked")
	protected <T> T runTestSetValue(String extra, String value, String schema)
			throws Exception {
		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				cmds.ghidraTraceInsertObj("Test.Objects[1]");
				%s
				cmds.ghidraTraceSetValue("Test.Objects[1]", "test", %s);
				cmds.ghidraTraceTxCommit();
				cmds.ghidraTraceSave();
				cmds.ghidraTraceDisconnect();
				/exit
				""".formatted(PREAMBLE, addr, TESTSETUP, extra, value, schema));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/Test")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = getLastSnapshot().getKey();
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Test.Objects[1]"));
			assertNotNull(object);
			TraceObjectValue test = object.getValue(snap, "test");
			return test == null ? null : (T) test.getValue();
		}
	}

	@Test
	public void testSetValueNull() throws Exception {
		assertNull(runTestSetValue("", "null", "VOID"));
	}

	@Test
	public void testSetValueBool() throws Exception {
		assertEquals(Boolean.TRUE, runTestSetValue("", "true", "BOOL"));
	}

	@Test
	public void testSetValueByte() throws Exception {
		assertEquals(Byte.valueOf((byte) 1), runTestSetValue("", "(byte)1", "BYTE"));
	}

	@Test
	public void testSetValueChar() throws Exception {
		assertEquals(Character.valueOf('A'), runTestSetValue("", "'A'", "CHAR"));
	}

	@Test
	public void testSetValueShort() throws Exception {
		assertEquals(Short.valueOf((short) 1), runTestSetValue("", "(short)1", "SHORT"));
	}

	@Test
	public void testSetValueInt() throws Exception {
		assertEquals(Integer.valueOf(1), runTestSetValue("", "(int)1", "INT"));
	}

	@Test
	public void testSetValueLong() throws Exception {
		assertEquals(Long.valueOf(1), runTestSetValue("", "(long)1", "LONG"));
	}

	@Test
	public void testSetValueString() throws Exception {
		assertEquals("HelloWorld!", runTestSetValue("", "\"HelloWorld!\"", "STRING"));
	}

	@Test
	public void testSetValueBoolArr() throws Exception {
		assertArrayEquals(new boolean[] { true, false },
			runTestSetValue("", "List.of(true,false)", "BOOL_ARR"));
	}

	@Test
	public void testSetValueShortArrUsingArray() throws Exception {
		assertArrayEquals(new short[] { 'H', 0, 'W' },
			runTestSetValue("", "List.of((short)'H',(short)0,(short)'W')", "SHORT_ARR"));
	}

	@Test
	public void testSetValueIntArrayUsingMixedArray() throws Exception {
		assertArrayEquals(new int[] { 'H', 0, 'W' },
			runTestSetValue("", "List.of((int)'H',0,(int)'W')", "INT_ARR"));
	}

	@Test
	public void testSetValueIntArrUsingArray() throws Exception {
		assertArrayEquals(new int[] { 1, 2, 3, 4 },
			runTestSetValue("", "List.of(1,(int)2L,3,4)", "INT_ARR"));
	}

	@Test
	public void testSetValueLongArr() throws Exception {
		assertArrayEquals(new long[] { 1, 2, 3, 4 },
			runTestSetValue("", "List.of(1L,(long)2,3L,4L)", "LONG_ARR"));
	}

	@Test
	public void testSetValueStringArr() throws Exception {
		assertArrayEquals(new String[] { "1", "A", "dead", "beef" },
			runTestSetValue("", "List.of(\"1\",\"A\",\"dead\",\"beef\")", "STRING_ARR"));
	}

	@Test
	public void testSetValueAddress() throws Exception {
		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				cmds.ghidraTraceInsertObj("Test.Objects[1]")
				cmds.ghidraTraceSetValue("VMs", "test", pc)
				cmds.ghidraTraceTxCommit();
				cmds.ghidraTraceSave();
				cmds.ghidraTraceDisconnect();
				/exit
				""".formatted(PREAMBLE, addr, HWSETUP_W_STATE));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = getLastSnapshot().getKey();
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(TraceObjectKeyPath.parse("VMs"));
			assertNotNull(object);
			TraceObjectValue value = object.getValue(snap, "test");
			Address address = (Address) value.getValue();
			assertEquals(0x1451L, address.getOffset());
			assertEquals("ram", address.getAddressSpace().getName());
		}
	}

	@Test
	public void testSetValueObject() throws Exception {
		runThrowError(
			addr -> """
					%s
					cmds.ghidraTraceConnect("%s");
					%s
					cmds.ghidraTraceInsertObj("Test.Objects[1]")
					cmds.ghidraTraceSetValue("VMs", "test", cmds.proxyObject(manager.getCurrentThread()))
					cmds.ghidraTraceTxCommit();
					cmds.ghidraTraceSave();
					cmds.ghidraTraceDisconnect();
					/exit
					"""
					.formatted(PREAMBLE, addr, HWSETUP_W_STATE));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = getLastSnapshot().getKey();
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(TraceObjectKeyPath.parse("VMs"));
			assertNotNull(object);
			TraceObjectValue value = object.getValue(snap, "test");
			TraceObject ret = (TraceObject) value.getValue();
			TraceObject orig = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(
						TraceObjectKeyPath.parse("VMs[OpenJDK 64-Bit Server VM].Threads[main]"));
			assertNotNull(ret);
			assertEquals(orig, ret);
		}
	}

	@Test
	public void testRetainValues() throws Exception {
		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				cmds.ghidraTraceInsertObj("Test.Objects[1]");
				cmds.ghidraTraceSetValue("Test.Objects[1]", "[1]", "'A'");
				cmds.ghidraTraceSetValue("Test.Objects[1]", "[2]", "'B'");
				cmds.ghidraTraceSetValue("Test.Objects[1]", "[3]", "'C'");
				cmds.ghidraTraceSetSnap(10);
				cmds.ghidraTraceRetainValues("--elements", "Test.Objects[1]", Set.of("[1]","[3]"));
				cmds.ghidraTraceTxCommit();
				cmds.ghidraTraceSave();
				cmds.ghidraTraceDisconnect();
				/exit
				""".formatted(PREAMBLE, addr, TESTSETUP));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/Test")) {
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
				cmds.ghidraTraceConnect("%s");
				cmds.ghidraTraceStart(null);
				cmds.ghidraTraceTxStart("Create Object");
				System.out.println("---Id---");
				cmds.ghidraTraceCreateObj("Test.Objects[1]");
				cmds.ghidraTraceInsertObj("Test.Objects[1]")
				System.out.println("---");
				cmds.ghidraTraceTxCommit();
				RmiTraceObject obj = cmds.ghidraTraceGetObj("Test.Objects[1]");
				System.out.println("---GetObject---");
				System.out.println(obj.getPath());
				System.out.println("---");
				cmds.ghidraTraceSave();
				/exit
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/jdi/noname")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			TraceObject object = tb.trace.getObjectManager()
					.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Test.Objects[1]"));
			assertNotNull(object);
			assertEquals("Test.Objects[1]", extractOutSection(out, "---GetObject---"));
		}
	}

	@Test // Good enough for the moment
	public void testGetValues() throws Exception {
		String out = runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				cmds.ghidraTraceSetValue("Test.Objects[1]", "vnull", "None");
				cmds.ghidraTraceSetValue("Test.Objects[1]", "vbool", true);
				cmds.ghidraTraceSetValue("Test.Objects[1]", "vbyte", "(char)1");
				cmds.ghidraTraceSetValue("Test.Objects[1]", "vchar", "'A'");
				cmds.ghidraTraceSetValue("Test.Objects[1]", "vshort", 2);
				cmds.ghidraTraceSetValue("Test.Objects[1]", "vint", 3);
				cmds.ghidraTraceSetValue("Test.Objects[1]", "vlong", 4L);
				cmds.ghidraTraceSetValue("Test.Objects[1]", "vstring", "Hello");
				List vboolarr = List.of(true,false);
				cmds.ghidraTraceSetValue("Test.Objects[1]", "vboolarr", vboolarr);
				List vshortarr = List.of((short)1, (short)2, (short)3);
				cmds.ghidraTraceSetValue("Test.Objects[1]", "vshortarr", vshortarr);
				List vintarr = List.of(1, 2, 3);
				cmds.ghidraTraceSetValue("Test.Objects[1]", "vintarr", vintarr);
				List vlongarr = List.of(1L, 2L, 3L);
				cmds.ghidraTraceSetValue("Test.Objects[1]", "vlongarr", vlongarr);
				List vstrarr = List.of("uno", "2", "iii");
				cmds.ghidraTraceSetValue("Test.Objects[1]", "vstrarr", vstrarr);
				cmds.ghidraTraceTxCommit();
				System.out.println("---GetValues---");
				cmds.ghidraTraceGetValues("Test.Objects[1].");
				System.out.println("---");
				cmds.ghidraTraceSave();
				cmds.ghidraTraceDisconnect();
				/exit
				""".formatted(PREAMBLE, addr, TESTSETUP));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/Test")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			assertEquals(
				"Parent          Key       Span      Value         Type      \n" +
					"Test.Objects[1] [0..+inf) vbool     true          BOOL      \n" +
					"Test.Objects[1] [0..+inf) vboolarr  [true, false] BOOL_ARR  \n" +
					"Test.Objects[1] [0..+inf) vbyte     (char)1       STRING    \n" +
					"Test.Objects[1] [0..+inf) vchar     'A'           STRING    \n" +
					"Test.Objects[1] [0..+inf) vint      3             INT       \n" +
					"Test.Objects[1] [0..+inf) vintarr   [1, 2, 3]     INT_ARR   \n" +
					"Test.Objects[1] [0..+inf) vlong     4             LONG      \n" +
					"Test.Objects[1] [0..+inf) vlongarr  [1, 2, 3]     LONG_ARR  \n" +
					"Test.Objects[1] [0..+inf) vnull     None          STRING    \n" +
					"Test.Objects[1] [0..+inf) vshort    2             INT       \n" +
					"Test.Objects[1] [0..+inf) vshortarr [1, 2, 3]     SHORT_ARR \n" +
					"Test.Objects[1] [0..+inf) vstrarr   [uno, 2, iii] STRING_ARR\n" +
					"Test.Objects[1] [0..+inf) vstring   Hello         STRING",
				extractOutSection(out, "---GetValues---").replaceAll("\r", ""));
// TODO:
//					Test.Objects[1] vbytearr  [0,+inf) b'\\x01\\x02\\x03' BYTE_ARR
//					Test.Objects[1] vchararr  [0,+inf) 'Hello'         CHAR_ARR
//					Test.Objects[1] vobj      [0,+inf) Test.Objects[1] OBJECT
		}
	}

	// @Test
	public void testGetValuesRng() throws Exception {
		Unfinished.TODO();
	}

	@Test
	public void testActivateObject() throws Exception {
		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				cmds.ghidraTraceActivate("VMs[OpenJDK 64-Bit Server VM].Threads[Finalizer]")
				cmds.ghidraTraceTxCommit();
				cmds.ghidraTraceSave();
				/exit
				""".formatted(PREAMBLE, addr, HWSETUP_W_STATE));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
			assertEquals("VMs[OpenJDK 64-Bit Server VM].Threads[Finalizer]",
				traceManager.getCurrentObject().getCanonicalPath().toString());
		}
	}

	//@Test FAIL - Can't seem to get any definedUnits
	public void testDisassemble() throws Exception {
		String out = runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				System.out.println("---Disassemble---");
				cmds.ghidraTraceDisassemble(pc)
				System.out.println("---");
				cmds.ghidraTraceTxCommit();
				cmds.ghidraTraceSave();
				/exit
				""".formatted(PREAMBLE, addr, HWSETUP_W_STATE));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = getLastSnapshot().getKey();
			// Not concerned about specifics, so long as disassembly occurs
			long total = 0;
			for (CodeUnit cu : tb.trace.getCodeManager().definedUnits().get(snap, true)) {
				total += cu.getLength();
			}
			String extract = extractOutSection(out, "---Disassemble---");
			String[] split = extract.split("\r\n");
			assertEquals("Disassembled %d bytes".formatted(total),
				split[0]);
		}
	}

	@Test
	public void testPutVMs() throws Exception {
		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				cmds.ghidraTracePutVMs();
				cmds.ghidraTraceTxCommit();
				cmds.ghidraTraceSave();
				/exit
				""".formatted(PREAMBLE, addr, HWSETUP_W_STATE));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = getLastSnapshot().getKey();
			Collection<TraceObject> vms = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(snap), PathPredicates.parse("VMs[]"))
					.map(p -> p.getDestination(null))
					.toList();
			assertEquals(1, vms.size());
		}
	}

	@Test
	public void testPutProcesses() throws Exception {
		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				cmds.ghidraTracePutProcesses();
				cmds.ghidraTraceTxCommit();
				cmds.ghidraTraceSave();
				/exit
				""".formatted(PREAMBLE, addr, HWSETUP_W_STATE));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = getLastSnapshot().getKey();
			Collection<TraceObject> processes = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(snap), PathPredicates.parse("VMs[].Processes"))
					.map(p -> p.getDestination(null))
					.toList();
			assertEquals(1, processes.size());
		}
	}

	@Test
	public void testPutModules() throws Exception {
		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				cmds.ghidraTracePutModules();
				cmds.ghidraTraceTxCommit();
				cmds.ghidraTraceSave();
				/exit
				""".formatted(PREAMBLE, addr, HWSETUP_W_STATE));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			Collection<? extends TraceModule> all = tb.trace.getModuleManager().getAllModules();
			TraceModule mod =
				Unique.assertOne(all.stream().filter(m -> m.getName().contains("Thread.class")));
			assertEquals(tb.addr(0x1000), Objects.requireNonNull(mod.getBase()));
		}
	}

	@Test
	public void testPutThreads() throws Exception {
		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				cmds.ghidraTracePutThreads();
				cmds.ghidraTraceTxCommit();
				cmds.ghidraTraceSave();
				cmds.ghidraTraceDisconnect();
				/exit
				""".formatted(PREAMBLE, addr, HWSETUP_W_STATE));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			Collection<? extends TraceThread> threads = tb.trace.getThreadManager().getAllThreads();
			assertEquals(4, threads.size());
			Set<String> names = new HashSet<>();
			for (TraceThread t : threads) {
				String path = t.getPath();
				names.add(path.substring(path.lastIndexOf("[")));
			}
			assertTrue(names.contains("[main]"));
			assertTrue(names.contains("[Finalizer]"));
			assertTrue(names.contains("[Reference Handler]"));
			assertTrue(names.contains("[Signal Dispatcher]"));
		}
	}

	@Test
	public void testPutFrames() throws Exception {
		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				cmds.ghidraTracePutFrames();
				cmds.ghidraTraceTxCommit();
				cmds.ghidraTraceSave();
				cmds.ghidraTraceDisconnect();
				/exit
				""".formatted(PREAMBLE, addr, HWSETUP_W_STATE));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = getLastSnapshot().getKey();
			List<TraceObject> stack = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(snap),
						PathPredicates.parse("VMs[].Threads[main].Stack[]"))
					.map(p -> p.getDestination(null))
					.toList();
			assertEquals(1, stack.size());
		}
	}

	@Test
	public void testPutRegions() throws Exception {
		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				cmds.ghidraTracePutModules();
				cmds.ghidraTraceTxCommit();
				cmds.ghidraTraceSave();
				/exit
				""".formatted(PREAMBLE, addr, HWSETUP_W_STATE));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			Collection<? extends TraceMemoryRegion> all =
				tb.trace.getMemoryManager().getAllRegions();
			assertThat(all.size(), greaterThan(90));
		}
	}

	@Test
	public void testEvents() throws Exception {
		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				MethodEntryRequest brkReq = vm.eventRequestManager().createMethodEntryRequest();
				cmds.ghidraTracePutEvents();
				cmds.ghidraTraceTxCommit();
				cmds.ghidraTraceSave();
				/exit
				""".formatted(PREAMBLE, addr, HWSETUP_W_STATE));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = getLastSnapshot().getKey();
			List<TraceObjectValue> events = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(snap),
						PathPredicates.parse("VMs[].Events[]"))
					.map(p -> p.getLastEntry())
					.sorted(Comparator.comparing(TraceObjectValue::getEntryKey))
					.toList();
			assertEquals(2, events.size());
		}
	}

	@Test
	public void testPutBreakpoints() throws Exception {
		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				%s
				Location loc = manager.getCurrentLocation();
				BreakpointRequest brkReq = vm.eventRequestManager().createBreakpointRequest(loc);
				cmds.ghidraTracePutBreakpoints();
				cmds.ghidraTraceTxCommit();
				cmds.ghidraTraceSave();
				/exit
				""".formatted(PREAMBLE, addr, HWSETUP_W_STATE));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = getLastSnapshot().getKey();
			List<TraceObjectValue> breaks = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(snap),
						PathPredicates.parse("VMs[].Breakpoints[]"))
					.map(p -> p.getLastEntry())
					.sorted(Comparator.comparing(TraceObjectValue::getEntryKey))
					.toList();
			assertEquals(1, breaks.size());
			AddressRange rangeMain =
				breaks.get(0).getChild().getValue(snap, "Range").castValue();
			Address bp1 = rangeMain.getMinAddress();
			assertEquals(0x1451L, bp1.getOffset());
		}
	}

	@Test
	public void testPutBreakpoints2() throws Exception {
		runThrowError(
			addr -> """
					%s
					cmds.ghidraTraceConnect("%s");
					%s
					String path = "VMs[OpenJDK 64-Bit Server VM].Classes[java.lang.Thread]";
					ReferenceType reftype = (ReferenceType) jdiManager.objForPath(path);
					Field field = reftype.fieldByName("tid");
					AccessWatchpointRequest brkReq = vm.eventRequestManager().createAccessWatchpointRequest(field);
					cmds.ghidraTracePutBreakpoints();
					cmds.ghidraTraceTxCommit();
					cmds.ghidraTraceSave();
					/exit
					"""
					.formatted(PREAMBLE, addr, HWSETUP_W_STATE));
		try (ManagedDomainObject mdo = openDomainObject("/New Traces/HelloWorld.class")) {
			tb = new ToyDBTraceBuilder((Trace) mdo.get());
			long snap = getLastSnapshot().getKey();
			List<TraceObjectValue> breaks = tb.trace.getObjectManager()
					.getValuePaths(Lifespan.at(snap),
						PathPredicates.parse("VMs[].Breakpoints[]"))
					.map(p -> p.getLastEntry())
					.sorted(Comparator.comparing(TraceObjectValue::getEntryKey))
					.toList();
			assertEquals(1, breaks.size());
			AddressRange rangeMain =
				breaks.get(0).getChild().getValue(snap, "Range").castValue();
			Address bp1 = rangeMain.getMinAddress();
			assertEquals(0L, bp1.getOffset());
			assertEquals("constantPool", bp1.getAddressSpace().getName());
		}
	}

	@Test
	public void testMinimal() throws Exception {
		runThrowError(addr -> """
				%s
				cmds.ghidraTraceConnect("%s")
				System.out.println("FINISHED")
				/exit
				""".formatted(PREAMBLE, addr));
	}

	private TraceSnapshot getLastSnapshot() {
		long snap = waitForValue(() -> tb.trace.getTimeManager().getMaxSnap());
		return tb.trace.getTimeManager().getSnapshot(snap, false);
	}
}
