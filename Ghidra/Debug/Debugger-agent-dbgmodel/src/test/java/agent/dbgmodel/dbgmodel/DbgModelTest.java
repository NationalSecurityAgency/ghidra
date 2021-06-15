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
package agent.dbgmodel.dbgmodel;

import static org.junit.Assert.*;

import java.io.*;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import org.junit.Before;
import org.junit.Test;

import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Variant.VARIANT;
import com.sun.jna.platform.win32.COM.COMException;
import com.sun.jna.platform.win32.COM.Unknown;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.dbgeng.DebugBreakpoint.BreakType;
import agent.dbgeng.dbgeng.DebugClient.DebugStatus;
import agent.dbgeng.dbgeng.DebugDataSpaces.*;
import agent.dbgeng.dbgeng.DebugModule.DebugModuleName;
import agent.dbgeng.dbgeng.DebugRegisters.DebugRegisterDescription;
import agent.dbgeng.dbgeng.DebugRegisters.DebugRegisterSource;
import agent.dbgeng.dbgeng.DebugValue.DebugInt64Value;
import agent.dbgmodel.dbgmodel.bridge.HostDataModelAccess;
import agent.dbgmodel.dbgmodel.datamodel.DataModelManager1;
import agent.dbgmodel.dbgmodel.datamodel.script.*;
import agent.dbgmodel.dbgmodel.debughost.*;
import agent.dbgmodel.dbgmodel.main.*;
import agent.dbgmodel.gadp.impl.WrappedDbgModel;
import agent.dbgmodel.impl.dbgmodel.bridge.HDMAUtil;
import agent.dbgmodel.impl.dbgmodel.debughost.DebugHostModuleImpl1;
import agent.dbgmodel.impl.dbgmodel.main.ModelPropertyAccessorInternal;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.*;
import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.NumericUtilities;

public class DbgModelTest extends AbstractGhidraHeadlessIntegrationTest {
	protected static HostDataModelAccess cachedAccess = null;
	protected static DebugClient cachedClient = null;

	protected HostDataModelAccess doDebugCreate() {
		System.out.println("Creating a client");
		return DbgModel.debugCreate();
	}

	protected HostDataModelAccess doDebugConnect() {
		System.out.println("Connecting to a client");
		String options = "tcp:Port=54321";
		return DbgModel.debugConnect(options);
	}

	protected void debugCreate() {
		//if (cachedClient == null) {
		cachedAccess = doDebugCreate();
		cachedClient = cachedAccess.getClient();
		//}
	}

	protected void debugConnect() {
		cachedAccess = doDebugConnect();
		cachedClient = cachedAccess.getClient();
	}

	protected HostDataModelAccess access;
	protected DebugClient client;
	protected DebugControl control;

	@Before
	public void setUp() {
		DbgEngTest.assumeDbgengDLLLoadable();
		debugCreate();
		//debugConnect();
		access = cachedAccess;
		client = cachedClient;
		control = client.getControl();
	}

	@Test
	public void testServer() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			control.execute(".server tcp:port=54321");

			int count = 0;
			try {
				while (true) {
					count++;
				}
			}
			catch (Exception e) {
				System.err.println(e);
			}
		}
	}

	@Test
	public void testOpenTrace() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			// NB:  This does not work!  TTDReplay must live in TTD\TTReplay.dll wherever
			//  dbgeng.dll lives
			//client.getControl().execute(".load c:\\Software\\windbg\\amd64\\ttd\\TTDReplay.dll");

			client.getControl().execute(".load TTDReplay.dll");
			client.getControl().execute(".load TTDAnalyze.dll");
			client.openDumpFileWide("notepad01.run");
		}
	}

	@Test
	public void testOpenTraceWithoutProcess() {
		final CompletableFuture<DebugProcessInfo> procInfo = new CompletableFuture<>();
		final CompletableFuture<DebugThreadInfo> threadInfo = new CompletableFuture<>();
		final CompletableFuture<Integer> procExit = new CompletableFuture<>();

		StringBuilder outputCapture = null;
		client.setEventCallbacks(new NoisyDebugEventCallbacksAdapter(DebugStatus.NO_CHANGE) {
			@Override
			public DebugStatus createProcess(DebugProcessInfo debugProcessInfo) {
				super.createProcess(debugProcessInfo);
				procInfo.complete(debugProcessInfo);
				return DebugStatus.BREAK;
			}

			@Override
			public DebugStatus createThread(DebugThreadInfo debugThreadInfo) {
				super.createThread(debugThreadInfo);
				threadInfo.complete(debugThreadInfo);
				return DebugStatus.BREAK;
			}

			@Override
			public DebugStatus exitProcess(int exitCode) {
				super.exitProcess(exitCode);
				procExit.complete(exitCode);
				return DebugStatus.BREAK;
			}
		});
		client.setOutputCallbacks(new DebugOutputCallbacks() {
			@Override
			public void output(int mask, String text) {
				System.out.print(text);
				if (outputCapture != null) {
					outputCapture.append(text);
				}
			}
		});

		client.openDumpFileWide("notepad01.run");
		control.waitForEvent();
		control.execute("g");
		control.waitForEvent();
		DebugProcessInfo pi = procInfo.getNow(null);
		DebugThreadInfo ti = threadInfo.getNow(null);
		DebugSystemObjects so = client.getSystemObjects();
		int currentProcessSystemId = so.getCurrentProcessSystemId();
		DebugProcessId currentProcessId = so.getCurrentProcessId();
		DebugThreadId currentThreadId = so.getCurrentThreadId();
		DebugProcessId eventProcess = so.getEventProcess();
		DebugThreadId eventThread = so.getEventThread();
		List<DebugProcessId> processes = so.getProcesses();
		List<DebugThreadId> threads = so.getThreads();
		System.err.println(threads);
	}

	@Test
	public void testInterfaces() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			HDMAUtil util = new HDMAUtil(access);
			DataModelManager1 manager = util.getManager();
			assertNotNull("manager not null", manager);
			DebugHost host = util.getHost();
			assertNotNull("host not null", host);
			//KeyStore defaultMetadata = host.getDefaultMetadata();
			//UnknownEx hostDefinedInterface = host.getHostDefinedInterface();

			ModelObject rootNamespace = util.getRootNamespace();
			assertNotNull("rootNamespace not null", rootNamespace);
			enumerate(rootNamespace, " ");
			//enumerateR(rootNamespace, " ");
			System.out.println("END");
		}
	}

	@Test
	public void testHammerEnumerate() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			HDMAUtil util = new HDMAUtil(access);
			DataModelManager1 manager = util.getManager();
			assertNotNull("manager not null", manager);
			DebugHost host = util.getHost();
			assertNotNull("host not null", host);

			ModelObject rootNamespace = util.getRootNamespace();
			assertNotNull("rootNamespace not null", rootNamespace);
			for (int i = 0; i < 10; i++) {
				enumerate(rootNamespace, " ");
				System.gc();
			}
			System.out.println("END");
		}
		UnknownWithUtils.ANALYZER.checkLeaks();
	}

	HashSet<String> seen = new HashSet<String>();

	private void enumerate(ModelObject obj, String tab) {
		String key;
		KeyEnumerator enumerateKeys = obj.enumerateKeyValues();
		do {
			key = enumerateKeys.getNext();
			ModelObject value = enumerateKeys.getValue();
			if (value == null || key == null || key.equals("Registers")) {
				continue;
			}
			//if (!value.getKind().equals(ModelObjectKind.OBJECT_METHOD)) {
			String desc = tab + key + ":" + value.getKind();
			if (value.getKind().equals(ModelObjectKind.OBJECT_INTRINSIC)) {
				desc += ":" + value.getIntrinsicValue();
			}
			if (!seen.contains(key)) {
				System.out.println(desc);
				seen.add(key);
				enumerate(value, tab + " ");
			}
			//}
		}
		while (key != null);

		List<ModelObject> children = obj.getElements();
		ListIterator<ModelObject> iter = children.listIterator();
		if (iter.hasNext()) {
			ModelObject child = iter.next();
			System.err.println(tab + child.toString());
			enumerate(child, tab + " ");
		}

		if (obj.getKind().equals(ModelObjectKind.OBJECT_TARGET_OBJECT)) {
			RawEnumerator enumerateRaw =
				obj.enumerateRawValues(SymbolKind.SYMBOL_FIELD.ordinal(), 0);
			while ((key = enumerateRaw.getNext()) != null) {
				ModelObject value = enumerateRaw.getValue();
				String desc = tab + key + ":" + value.getKind();
				if (value.getKind().equals(ModelObjectKind.OBJECT_INTRINSIC)) {
					desc += ":" + value.getIntrinsicValue();
				}
				if (!seen.contains(key.toString())) {
					System.out.println(desc);
					seen.add(key.toString());
					enumerate(value, tab + " ");
				}
			}
		}
	}

	@Test
	public void testGetChild() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			HDMAUtil util = new HDMAUtil(access);
			ModelObject currentProcess = util.getCurrentProcess();
			String ctlid = util.getCtlId(currentProcess);
			ModelObject process = util.getProcess(util.getCurrentSession(), ctlid);
			assertTrue(ctlid.equals(util.getCtlId(process)));
		}
	}

	@Test
	public void testEnv() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			//control.execute(".server tcp:port=54321");

			HDMAUtil util = new HDMAUtil(access);
			//DataModelManager1 manager = util.getManager();

			ModelObject currentProcess = util.getCurrentProcess();
			ModelObject env = currentProcess.getKeyValue("Environment");
			ModelObject eb = env.getKeyValue("EnvironmentBlock");
			System.out.println(eb.getKind());
			System.out.println(eb.toString());

			DebugHostType1 targetInfo = eb.getTargetInfo();
			//DebugHostContext context = targetInfo.getContext();
			System.out.println(targetInfo.getSymbolKind());
			System.out.println(targetInfo.getName());
			//DebugHostType1 type = targetInfo.getType();
			DebugHostModule1 containingModule = targetInfo.getContainingModule();
			System.out.println(containingModule.getName());
			DebugHostType1 typeByName = containingModule.findTypeByName("_PEB");
			System.out.println(typeByName.getName());

			//System.out.println(targetInfo.getOffset());
			System.out.println(targetInfo.getTypeKind());
			System.out.println(targetInfo.getSize());

			System.out.println(Integer.toHexString(targetInfo.getHashCode()));

			System.out.println(targetInfo.getPointerKind());

			DebugHostSymbolEnumerator enumerator =
				targetInfo.enumerateChildren(SymbolKind.SYMBOL, null);
			DebugHostSymbol1 next;
			while ((next = enumerator.getNext()) != null) {
				System.out.println(next.getName());
			}
		}
	}

	@Test
	public void testEnvEx() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			//control.execute(".server tcp:port=54321");

			HDMAUtil util = new HDMAUtil(access);
			DebugHost host = util.getHost();
			//DebugHostContext currentContext = host.getCurrentContext();
			//DataModelManager1 manager = util.getManager();

			ModelObject currentProcess = util.getCurrentProcess();
			ModelObject env = currentProcess.getKeyValue("Environment");
			ModelObject eb = env.getKeyValue("EnvironmentBlock");

			client.getControl().execute("dt nt!_PEB");
			client.getControl()
					.execute(
						"dx Debugger.State.DebuggerVariables.curprocess.Environment.EnvironmentBlock");
			System.err.println(eb.hashCode());
			System.err.println(eb.getLocation().Offset);
			DebugHostType2 targetInfo = (DebugHostType2) eb.getTargetInfo();
			DebugHostSymbolEnumerator enumerator =
				targetInfo.enumerateChildren(SymbolKind.SYMBOL, null);
			DebugHostSymbol1 next;
			while ((next = enumerator.getNext()) != null) {
				System.out.println(next.getName());
			}
			System.err.println(targetInfo.getTypeKind());

			System.err.println(eb.getKeyValueMap().size());
			System.err.println(eb.getElements().size());
			RawEnumerator enumeratorR = eb.enumerateRawValues(SymbolKind.SYMBOL.ordinal(), 0);
			String nextR;
			// SYMBOL, SYMBOL_CONSTANT, SYMBOL_DATA, SYMBOL_FIELD return the same values
			// SYMBOL_BASE_CLASS, SYMBOL_PUBLIC, SYMBOL_TYPE return nothing
			// SYMBOL_FUNCTION, SYMBOL_MODULE throw an error
			while ((nextR = enumeratorR.getNext()) != null) {
				System.out.println(nextR);
				System.out.println(enumeratorR.getKind());
			}
		}
	}

	/*
	@Test
	public void testPrintln() {
		CompletableFuture<String> cb = new CompletableFuture<>();
		client.setOutputCallbacks(new DebugOutputCallbacks() {
			@Override
			public void output(int mask, String text) {
				System.out.print(text);
				cb.complete(text);
			}
		});
		control.outln("Hello, World!");
		String back = cb.getNow(null);
		// NOTE: I'd like to be precise wrt/ new lines, but it seems to vary with version.
		assertEquals("Hello, World!", back.trim());
	}
	*/

	@Test
	public void testGetProcessSystemIds() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			HDMAUtil util = new HDMAUtil(access);
			ModelObject currentSession = util.getCurrentSession();
			String ctlid = util.getCtlId(currentSession);
			List<ModelObject> procs = util.getRunningProcesses(ctlid);
			System.out.println("Total: " + procs.size());
			procs.sort(null);
			for (ModelObject p : procs) {
				System.out.println("ID: " + util.getCtlId(p));
			}
		}
	}

	@Test
	public void testGetProcesses() {
		DebugSystemObjects so = access.getClient().getSystemObjects();
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();
			System.out.println(so.getNumberProcesses());

			HDMAUtil util = new HDMAUtil(access);
			ModelObject currentProcess = util.getCurrentProcess();
			String ctlid = util.getCtlId(currentProcess);
			System.out.println("ID: " + ctlid);
			List<DebugProcessId> processes = so.getProcesses();
			for (DebugProcessId id : processes) {
				System.out.println("ID: " + id);
				DebugProcessId pid = so.getProcessIdBySystemId(Integer.parseUnsignedInt(ctlid, 16));
				System.out.println("ID: " + pid);
			}
		}
	}

	@Test
	public void testGetProcessDescriptions() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			HDMAUtil util = new HDMAUtil(access);
			ModelObject currentSession = util.getCurrentSession();
			String ctlid = util.getCtlId(currentSession);
			List<ModelObject> procs = util.getRunningProcesses(ctlid);
			System.out.println("Total: " + procs.size());
			procs.sort(null);
			for (ModelObject p : procs) {
				try {
					System.out.println(p.toString());
				}
				catch (COMException e) {
					System.out
							.println("Error with PID " + util.getCtlId(p) + ": " + e.getMessage());
				}
			}
		}
	}

	@Test
	public void testGetRegistersNew() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			HDMAUtil util = new HDMAUtil(access);
			ModelObject currentThread = util.getCurrentThread();
			ModelObject registers = currentThread.getKeyValue("Registers").getKeyValue("User");
			Map<String, ModelObject> map = registers.getKeyValueMap();
			for (String key : map.keySet()) {
				ModelObject mo = map.get(key);
				Object value = mo.getValue();
				System.out.println(key + ":" + Long.toHexString(Long.parseLong(value.toString())));
			}
		}
	}

	@Test
	public void testGetAllRegisters() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			WrappedDbgModel dbgmodel = new WrappedDbgModel(access);
			Set<DebugRegisterDescription> descs = dbgmodel.getAllRegisterDescriptions();
			for (DebugRegisterDescription desc : descs) {
				System.out.println(desc.index + ":" + desc.name);
			}
		}
	}

	@Test
	public void testGetRegisters() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			List<String> out = maker.execCapture("r");
			String expected = out.stream().filter(s -> s.startsWith("rax")).findAny().get();

			WrappedDbgModel dbgmodel = new WrappedDbgModel(access);
			DebugRegisters regs = dbgmodel.getRegisters();
			List<Integer> indices = new ArrayList<>();
			int raxIdx = regs.getIndexByName("rax");
			int rbxIdx = regs.getIndexByName("rbx");
			int rcxIdx = regs.getIndexByName("rcx");
			indices.add(raxIdx);
			indices.add(rbxIdx);
			indices.add(rcxIdx);
			Map<Integer, DebugValue> values =
				regs.getValues(DebugRegisterSource.DEBUG_REGSRC_DEBUGGEE, indices);

			String actual = String.format("rax=%016x rbx=%016x rcx=%016x",
				((DebugInt64Value) values.get(raxIdx)).longValue(),
				((DebugInt64Value) values.get(rbxIdx)).longValue(),
				((DebugInt64Value) values.get(rcxIdx)).longValue());
			System.out.println(actual);
			assertEquals(expected, actual);
		}
	}

	@Test
	public void testSetCurrentThread() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			HDMAUtil util = new HDMAUtil(access);
			ModelObject currentProcess = util.getCurrentProcess();
			ModelObject currentThread = util.getCurrentThread();
			System.out.println(currentThread);
			String ctlid = util.getCtlId(currentThread);
			VARIANT v = new VARIANT(ctlid);
			currentProcess.switchTo(util.getManager(), v);
			currentThread = util.getCurrentThread();
			;
			System.out.println(currentThread);
		}
	}

	@Test
	public void testGetElements() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			HDMAUtil util = new HDMAUtil(access);
			List<ModelObject> children =
				util.getElements(List.of("Debugger", "Sessions[0]", "Processes"));
			for (ModelObject obj : children) {
				System.err.println(obj.getSearchKey());
			}
		}
	}

	@Test
	public void testGetAttributes() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			HDMAUtil util = new HDMAUtil(access);
			Map<String, ModelObject> map = util.getAttributes(List.of("Debugger", "Sessions"));
			for (String key : map.keySet()) {
				System.err.println(key);
			}
		}
	}

	@Test
	public void testCall() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			HDMAUtil util = new HDMAUtil(access);
			DataModelManager1 manager = util.getManager();
			Pointer[] args = new Pointer[0];
			//VARIANT.ByReference vbr = new VARIANT.ByReference(v);
			//ModelObject mo = manager.createIntrinsicObject(ModelObjectKind.OBJECT_INTRINSIC, vbr);
			//args[0] = mo.getPointer();
			ModelObject sessions = util.getSessionOf(null);
			ModelMethod f = sessions.getMethod("Last");
			ModelObject ret = f.call(sessions, 0, args);
			System.err.println("=====>" + ret.getSearchKey());
		}
	}

	@Test
	public void testCallWithParameter() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			HDMAUtil util = new HDMAUtil(access);
			DebugHost host = util.getHost();
			DebugHostEvaluator2 eval = host.asEvaluator();
			Pointer[] args = new Pointer[1];
			ModelObject process = util.getCurrentProcess();
			ModelObject threads = process.getKeyValue("Threads");
			DebugHostContext context = host.getCurrentContext();
			ModelObject mo =
				eval.evaluateExtendedExpression(context, new WString("c => c.Id"), threads);
			args[0] = mo.getPointer();
			ModelMethod f = threads.getMethod("OrderByDescending");
			ModelObject ret = f.call(threads, 1, args);
			List<ModelObject> children = ret.getElements();
			for (ModelObject child : children) {
				System.err.println("=====>" + child.getSearchKey());
			}
		}
	}

	@Test
	public void testCallWithParametersEx() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			HDMAUtil util = new HDMAUtil(access);
			DebugHost host = util.getHost();
			DebugHostEvaluator2 eval = host.asEvaluator();
			ModelObject process = util.getCurrentProcess();
			ModelObject modules = process.getKeyValue("Modules");
			DebugHostContext context = host.getCurrentContext();
			ModelObject mo = eval.evaluateExtendedExpression(context,
				new WString("OrderByDescending(c => c.BaseAddress)"), modules);
			List<ModelObject> children = mo.getElements();
			for (ModelObject child : children) {
				ModelObject value = child.getKeyValue("BaseAddress");
				System.err.println("=====>" + child.getSearchKey() + ":" + value);
			}
		}
	}

/*
	@Test
	public void testSetSingleRegister() {
		try (ProcMaker maker = new ProcMaker(client,"notepad")) {
			maker.start();

			DebugRegisters regs = client.getRegisters();
			regs.setValueByName("rax", new DebugInt64Value(0x0102030405060708L));

			List<String> out = maker.execCapture("r");
			String actual =
				out.stream().filter(s -> s.startsWith("rax")).findAny().get().split("\\s+")[0];
			assertEquals("rax=0102030405060708", actual);
		}
	}

	@Test
	public void testSetRegisters() {
		try (ProcMaker maker = new ProcMaker(client,"notepad")) {
			maker.start();

			DebugRegisters regs = client.getRegisters();
			// Purposefully choosing non-linked variant.
			// Want to know that order does not make a difference.
			Map<Integer, DebugValue> values = new HashMap<>();
			values.put(regs.getIndexByName("rax"), new DebugInt64Value(0x0102030405060708L));
			values.put(regs.getIndexByName("rbx"), new DebugInt64Value(0x1122334455667788L));
			values.put(regs.getIndexByName("rcx"), new DebugInt64Value(0x8877665544332211L));
			regs.setValues(DebugRegisterSource.DEBUG_REGSRC_DEBUGGEE, values);

			List<String> out = maker.execCapture("r");
			String actual = out.stream().filter(s -> s.startsWith("rax")).findAny().get();
			assertEquals("rax=0102030405060708 rbx=1122334455667788 rcx=8877665544332211", actual);
		}
	}

	@Test
	public void testQueryVirtual() {
		// Also, an experiment to figure out how it works
		try (ProcMaker maker = new ProcMaker(client,"notepad")) {
			maker.start();

			List<DebugMemoryBasicInformation> collected1 = new ArrayList<>();
			try {
				long last = 0;
				long offset = 0;
				do {
					System.out.print(Long.toHexString(offset) + ": ");
					DebugMemoryBasicInformation info = client.getDataSpaces().queryVirtual(offset);
					System.out.println(info);
					collected1.add(info);
					last = offset;
					offset += info.regionSize;
				}
				while (Long.compareUnsigned(last, offset) < 0);
			}
			catch (COMException e) {
				if (!e.getMessage().contains("HRESULT: 80004002")) {
					throw e;
				}
			}

			List<DebugMemoryBasicInformation> collected2 = new ArrayList<>();
			for (DebugMemoryBasicInformation info : client.getDataSpaces().iterateVirtual(0)) {
				collected2.add(info);
			}

			assertTrue(collected1.size() > 0);
			assertEquals(collected1, collected2);
		}
	}
*/

	@Test
	public void testModules() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			HDMAUtil util = new HDMAUtil(access);
			DebugHost host = util.getHost();
			DebugHostSymbols symbols = host.asSymbols();
			DebugHostSymbolEnumerator enumerator =
				symbols.enumerateModules(util.getCurrentContext());
			DebugHostSymbol1 next;
			while ((next = enumerator.getNext()) != null) {
				DebugHostModule1 module = next.asModule();
				System.out.println("  Ctxt: " + module.getContext());
				System.out.println(
					"  Kind: " + SymbolKind.values()[module.getSymbolKind().ordinal()]);
				System.out.println("  Load: " + module.getName().toString());
				DebugHostModule1 containingModule = module.getContainingModule();
				System.out.println("  CMod: " + containingModule);

				System.out.println("   Img: " + module.getImageName(true).toString());
				LOCATION base = module.getBaseLocation();
				System.out.println("  Base: " + Long.toHexString(base.Offset.longValue()));
				module.getVersion();
				DebugHostModuleImpl1 impl = (DebugHostModuleImpl1) module;
				System.out.println("  FVer: " + Long.toHexString(impl.getFileVersion()));
				System.out.println("  Pvar: " + Long.toHexString(impl.getProductVersion()));
			}
		}
	}

	@Test
	public void testStack() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			HDMAUtil util = new HDMAUtil(access);
			ModelObject currentStack = util.getCurrentStack();
			ModelObject frames = currentStack.getKeyValue("Frames");
			List<ModelObject> children = frames.getElements();
			for (ModelObject child : children) {
				System.out.println(child);
				Map<String, ModelObject> map = child.getKeyValueMap();
				for (String key : map.keySet()) {
					ModelObject value = map.get(key);
					System.out.println(key + ":" + value);
					if (value.getKind().equals(ModelObjectKind.OBJECT_PROPERTY_ACCESSOR)) {
						Unknown v = (Unknown) value.getIntrinsicValue();
						System.out.println(v);
						ModelPropertyAccessorInternal ifc =
							ModelPropertyAccessorInternal.tryPreferredInterfaces(v::QueryInterface);
						System.out.println(ifc);
						ModelObject result = ifc.getValue("All", null);
						System.out.println(result);
					}
				}
			}
		}
	}

	@Test
	public void testReadMemory() throws FileNotFoundException, IOException {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			int len = 256;

			HDMAUtil util = new HDMAUtil(access);
			DebugHostContext currentContext = util.getCurrentContext();
			DebugHost host = util.getHost();
			DebugHostSymbols symbols = host.asSymbols();
			DebugHostModule1 module = symbols.findModuleByName(currentContext, "notepad");
			LOCATION base = module.getBaseLocation();
			System.out.println("Base: " + Long.toHexString(base.Offset.longValue()));

			DebugHostMemory1 memory = host.asMemory();

			ByteBuffer data = ByteBuffer.allocate(len);
			memory.readBytes(currentContext, base, data, len);
			System.out.println(NumericUtilities.convertBytesToString(data.array()));

			// TODO: Avoid hardcoding path to notepad
			try (FileInputStream fis = new FileInputStream("C:\\Windows\\notepad.exe")) {
				byte[] fromFile = new byte[len];
				fis.read(fromFile);
				System.out.println(NumericUtilities.convertBytesToString(fromFile));
				assertArrayEquals(fromFile, data.array());
			}

			//data.clear();
			//data.putInt(0x12345678);
			//client.getDataSpaces().readVirtual(notepadModule.getBase(), data, data.remaining());
			//data.flip();

			//assertEquals(0x12345678, data.getInt());
		}
	}

	@Test
	public void testScriptInterface() throws FileNotFoundException, IOException {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			client.getControl()
					.execute(".load c:\\Software\\windbg\\amd64\\winext\\JSProvider.dll");
			client.getControl().execute(".load c:\\Software\\windbg\\amd64\\ttd\\TTDReplayCPU.dll");
			client.getControl().execute(".load c:\\Software\\windbg\\amd64\\ttd\\TTDAnalyze.dll");
			client.getControl().execute(".load c:\\Software\\windbg\\amd64\\ttd\\TtdExt.dll");
			client.getControl().execute("!tt 1:0");

			HDMAUtil util = new HDMAUtil(access);
			DebugHostContext currentContext = util.getCurrentContext();
			DebugHost host = util.getHost();
			DebugHostScriptHost scriptHost = host.asScriptHost();
			DataModelManager1 manager = util.getManager();
			DataModelScriptManager scriptManager = manager.asScriptManager();
			//DataModelScriptProvider jsProvider =
			//	scriptManager.findProviderForScriptType("JavaScript");
			DataModelScriptProviderEnumerator enumerator =
				scriptManager.enumeratorScriptProviders();
			DataModelScriptProvider next;
			while ((next = enumerator.getNext()) != null) {
				System.out.println(next.getName());
				DataModelScriptTemplateEnumerator enumerator2 = next.enumerateTemplates();
				DataModelScriptTemplate nextTemplate;
				while ((nextTemplate = enumerator2.getNext()) != null) {
					System.out.println(nextTemplate.getName());
					System.out.println(nextTemplate.getDescription());
				}
			}
		}
	}

	@Test
	public void testBreakpoints() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			DebugBreakpoint bpt = control.addBreakpoint(BreakType.CODE);
			System.out.println("Breakpoint id: " + bpt.getId());
			System.out.println("Flags: " + bpt.getFlags());
			DebugBreakpoint bpt2 = control.getBreakpointById(bpt.getId());
			assertEquals(bpt, bpt2);

			HDMAUtil util = new HDMAUtil(access);
			ModelObject currentProcess = util.getCurrentProcess();

			ModelObject bpts = currentProcess.getKeyValue("Debug").getKeyValue("Breakpoints");
			List<ModelObject> children = bpts.getElements();
			for (ModelObject child : children) {
				//List<ModelObject> gc = child.getChildren();
				Map<String, ModelObject> pairs = child.getKeyValueMap();
				for (String key : pairs.keySet()) {
					System.out.println(key);
				}
			}

		}
	}

	@Test
	public void testSymbols() {
		try (ProcMaker maker =
			new ProcMaker(client, "c:\\Users\\user\\Desktop\\ConsoleApplication1.exe")) {
			maker.start();

			DebugSymbols ds = client.getSymbols();
			System.out.println(ds.getSymbolPath());
			ds.setSymbolPath("srv*c:\\Symbols*https://msdl.microsoft.com/downloads/symbols");
			System.out.println(ds.getSymbolOptions());
			ds.setSymbolOptions(0x80000046);

			WrappedDbgModel dbgmodel = new WrappedDbgModel(access);
			ModelObject symbolSettings = dbgmodel.getUtil().getSettings().getKeyValue("Symbols");
			ModelObject sympath = symbolSettings.getKeyValue("Sympath");
			sympath.getIntrinsicValue();
			List<DebugHostModule1> modules2 = dbgmodel.getDebugHostModules();
			for (DebugHostModule1 module : modules2) {
				System.out.println(module.getName().toString());
				System.out.println(module.getSymbolKind());

				List<DebugSymbolId> symbol0 = client.getSymbols().getSymbolIdsByName("");
				System.out.println(symbol0.size());

				try {
					DebugHostSymbolEnumerator enumerator =
						module.enumerateChildren(SymbolKind.SYMBOL_PUBLIC, null);
					if (enumerator != null) {
						DebugHostSymbol1 next;
						int count = 0;
						while ((next = enumerator.getNext()) != null) {

							System.out.println(next.getName() + ":" + next.getSymbolKind());
							if (next.getSymbolKind().equals(SymbolKind.SYMBOL_PUBLIC)) {
								DebugHostPublic pub = next.asPublic();
								try {
									System.out.println(pub.getLocationKind());
									System.out.println(pub.getLocation().Offset);
								}
								catch (Exception e) {
									e.printStackTrace();
								}
							}

							count++;
						}
						System.out.println(count);
					}
				}
				catch (Exception e) {
					e.printStackTrace();
				}
			}

			Set<DebugSymbolName> symbols = new LinkedHashSet<>();
			Set<String> modules = new LinkedHashSet<>();
			for (DebugSymbolName sym : client.getSymbols().iterateSymbolMatches("*")) {
				String[] parts = sym.name.split("!");
				symbols.add(sym);
				modules.add(parts[0]);
			}
			System.out.println("Total Symbols: " + symbols.size());
			System.out.println("Total Modules (by symbol name): " + modules.size());

			// These make assumptions that could be broken later.
			// It used to expect at least 10 modules (devised when testing on Win7). Now it's 5!
			assertTrue("Fewer than 1000 symbols: " + symbols.size(), symbols.size() > 1000);
			assertTrue("Fewer than 3 modules: " + modules.size(), modules.size() > 3);
		}
	}

	//@Test(expected = COMException.class)
	public void testModuleOutOfBounds() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			DebugModule umod = client.getSymbols()
					.getModuleByIndex(client.getSymbols().getNumberLoadedModules() + 1);
			System.out.println(umod.getBase());
		}
	}

	@Test
	public void testQueryVirtualWithModule() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			for (DebugMemoryBasicInformation info : client.getDataSpaces().iterateVirtual(0)) {
				if (info.state != PageState.FREE) {
					DebugModule mod = null;
					String name = "[NONE]";
					try {
						mod = client.getSymbols().getModuleByOffset(info.baseAddress, 0);
						name = mod.getName(DebugModuleName.IMAGE);
					}
					catch (COMException e) {
						name = "[ERR:" + e + "]";
					}
					System.out.println(String.format("%016x", info.baseAddress) + ":" +
						Long.toHexString(info.regionSize) + ":" + info.state + " from " + name +
						" " + info.type + info.protect);
				}
			}
		}
	}

	@Test
	public void testSymbolInfo() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			int count = 0;
			for (DebugSymbolId symid : client.getSymbols().getSymbolIdsByName("ntdll!*")) {
				//System.out.println(symid);
				DebugSymbolEntry syment = client.getSymbols().getSymbolEntry(symid);
				if (syment.typeId != 0) {
					System.out.println("  " + syment);
				}
				count++;
			}

			assertTrue(count > 10);
		}
	}

	//@Test
	public void testWriteMemory() {
		try (ProcMaker maker = new ProcMaker(client, "notepad")) {
			maker.start();

			// TODO: How to write to protected memory?
			// Debugger should be able to modify program code.
			DebugMemoryBasicInformation writable = null;
			space: for (DebugMemoryBasicInformation info : client.getDataSpaces()
					.iterateVirtual(0)) {
				for (PageProtection prot : info.protect) {
					if (prot.isWrite()) {
						writable = info;
						break space;
					}
				}
			}
			if (writable == null) {
				throw new AssertionError("No writable pages?");
			}
			System.out.println("writable: " + writable);
			ByteBuffer toWrite = ByteBuffer.allocate(10);
			toWrite.putInt(0x12345678);
			toWrite.putInt(0x89abcdef);
			toWrite.putShort((short) 0x5555);
			toWrite.flip();
			client.getDataSpaces().writeVirtual(writable.baseAddress, toWrite, toWrite.remaining());

			ByteBuffer toRead = ByteBuffer.allocate(10);
			client.getDataSpaces().readVirtual(writable.baseAddress, toRead, toRead.remaining());

			assertArrayEquals(toWrite.array(), toRead.array());
		}
	}

	/*
	@Test
	public void testFreezeUnfreeze() {
		try (ProcMaker maker = new ProcMaker(client,"notepad")) {
			maker.start();
	
			// Trying to see if any events will help me track frozen threads
			System.out.println("****Freezing");
			control.execute("~0 f");
			System.out.println("****Unfreezing");
			control.execute("~0 u");
			System.out.println("****Done");
			// Well, that result stinks.
			// There is no event to tell me about frozenness
		}
	}
	*/

	/*
	@Test
	@Ignore("I can't find a reliable means to detect the last thread. " +
		"There's supposed to be an initial break, but it is rarely reported. " +
		"I thought about toolhelp, but that presumes local live debugging.")
	public void testMultiThreadAttach() throws Exception {
		// I need to see how to attach to multi-threaded processes. There must be some event
		// or condition to indicate when all threads have been discovered.
		String specimen =
			Application.getOSFile("sctldbgeng", "expCreateThreadSpin.exe").getCanonicalPath();
		client.setOutputCallbacks(new DebugOutputCallbacks() {
			@Override
			public void output(int mask, String text) {
				System.out.print(text);
				System.out.flush();
			}
		});
		client.setEventCallbacks(new DebugEventCallbacksAdapter() {
			@Override
			public DebugStatus breakpoint(DebugBreakpoint bp) {
				control.outln("*** Breakpoint: " + bp);
				return DebugStatus.BREAK;
			}
	
			@Override
			public DebugStatus exception(DebugExceptionRecord64 exception, boolean firstChance) {
				control.outln("*** Exception: " + exception + "," + firstChance);
				return DebugStatus.BREAK;
			}
	
			@Override
			public DebugStatus createThread(DebugThreadInfo debugThreadInfo) {
				control.outln("*** CreateThread: " + debugThreadInfo);
				System.out.println("Threads: " + client.getSystemObjects().getThreads());
				return DebugStatus.BREAK;
			}
	
			@Override
			public DebugStatus createProcess(DebugProcessInfo debugProcessInfo) {
				control.outln("*** CreateProcess: " + debugProcessInfo);
				System.out.println("Threads: " + client.getSystemObjects().getThreads());
				return DebugStatus.BREAK;
			}
	
			@Override
			public DebugStatus exitThread(int exitCode) {
				control.outln("*** ExitThread: code=" + exitCode + ", " +
					client.getSystemObjects().getEventThread());
				System.out.println("Threads: " + client.getSystemObjects().getThreads());
				return DebugStatus.BREAK;
			}
	
			@Override
			public DebugStatus exitProcess(int exitCode) {
				control.outln("*** ExitProcess: code=" + exitCode + ", " +
					client.getSystemObjects().getEventProcess());
				System.out.println("Threads: " + client.getSystemObjects().getThreads());
				return DebugStatus.BREAK;
			}
	
			@Override
			public DebugStatus changeEngineState(BitmaskSet<ChangeEngineState> flags,
					long argument) {
				if (flags.contains(ChangeEngineState.EXECUTION_STATUS)) {
					control.outln("*** ExecutionStatus: " + control.getExecutionStatus());
				}
				return DebugStatus.NO_CHANGE;
			}
		});
		try (DummyProc proc = new DummyProc(specimen)) {
			System.out.println("Started " + specimen + " with PID=" + proc.pid);
			Thread.sleep(1000);
			System.out.println("Attaching...");
			client.attachProcess(client.getLocalServer(), proc.pid, BitmaskSet.of());
			if (true) {
				for (int i = 0; i < 10; i++) {
					System.out.println("WAIT " + i + "...");
					control.waitForEvent(100);
					System.out.println("STATUS: " + control.getExecutionStatus());
					System.out.println("DONE " + i);
					// control.execute("~*");
				}
			}
		}
		finally {
			client.setEventCallbacks(null);
		}
	}
	*/

	@Test
	public void testPrompt() throws Exception {

	}
}
