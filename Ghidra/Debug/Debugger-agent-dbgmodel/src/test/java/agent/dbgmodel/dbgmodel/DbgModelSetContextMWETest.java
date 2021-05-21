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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.*;
import java.util.*;

import org.junit.Before;
import org.junit.Test;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.dbgeng.DebugBreakpoint.BreakFlags;
import agent.dbgeng.dbgeng.DebugBreakpoint.BreakType;
import agent.dbgeng.dbgeng.DebugClient.*;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_STACK_FRAME;
import agent.dbgmodel.dbgmodel.bridge.HostDataModelAccess;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.impl.dbgmodel.bridge.HDMAUtil;
import ghidra.comm.util.BitmaskSet;
import ghidra.dbg.util.PathUtils;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.Msg;

public class DbgModelSetContextMWETest extends AbstractGhidraHeadlessIntegrationTest {

	@Before
	public void setUp() {
		DbgEngTest.assumeDbgengDLLLoadable();
	}

	@Test
	public void testMWE() throws IOException {
		HostDataModelAccess access = DbgModel.debugCreate();
		DebugClient client = access.getClient();
		DebugControl control = client.getControl();
		DebugRegisters registers = client.getRegisters();
		DebugSystemObjects so = client.getSystemObjects();
		HDMAUtil util = new HDMAUtil(access);

		var cb = new NoisyDebugEventCallbacksAdapter(DebugStatus.GO) {
			volatile boolean hit = false;

			private void dumpAllThreads(Runnable runnable, boolean reverse, boolean shuffle) {
				try {
					DebugThreadId restore = so.getCurrentThreadId();
					try {
						List<DebugThreadId> threads = so.getThreads();
						if (shuffle) {
							Collections.shuffle(threads);
						}
						if (reverse) {
							Collections.reverse(threads);
						}
						for (DebugThreadId id : threads) {
							so.setCurrentThreadId(id);
							runnable.run();
						}
					}
					finally {
						so.setCurrentThreadId(restore);
					}
				}
				catch (Exception e) {
					Msg.error(this, "Issue getting current thread: " + e);
				}
			}

			private void dumpRegsViaDX() {
				DebugThreadId id = so.getCurrentThreadId();
				if (id.id == -1) {
					return;
				}

				int pid = so.getCurrentProcessSystemId();
				int tid = so.getCurrentThreadSystemId();
				String prefix = String.format(
					"Debugger.Sessions[0x0].Processes[0x%x].Threads[0x%x]", pid, tid);

				try {
					control.execute("dx " + prefix + ".Registers.User");
				}
				catch (Exception e) {
					Msg.error(this, "Could not dump regs of " + prefix + ": " + e);
				}
			}

			private void dumpFrame0ViaDX() {
				DebugThreadId id = so.getCurrentThreadId();
				if (id.id == -1) {
					return;
				}

				int pid = so.getCurrentProcessSystemId();
				int tid = so.getCurrentThreadSystemId();
				String prefix = String.format(
					"Debugger.Sessions[0x0].Processes[0x%x].Threads[0x%x]", pid, tid);

				String path = prefix + ".Stack.Frames[0x0].Attributes.InstructionOffset";
				List<String> parsed = PathUtils.parse(path);
				try {
					//for (int i = 0; i < parsed.size(); i++) {
					//List<String> sub = parsed.subList(0, i + 1);
					List<String> sub = parsed;
					ModelObject obj = util.getTerminalModelObject(sub);
					Msg.info(this, PathUtils.toString(sub) + "=" + obj);
					//}
				}
				catch (Exception e) {
					Msg.error(this, "Could not get object " + path + ": " + e);
				}

				try {
					control.execute("dx " + path);
				}
				catch (Exception e) {
					Msg.error(this, "Could not execute dx " + path + ": " + e);
				}
			}

			private void dumpFrame0ViaK() {
				DebugThreadId id = so.getCurrentThreadId();
				if (id.id == -1) {
					return;
				}
				try {
					DebugStackInformation stackInfo = control.getStackTrace(0, 0, 0);
					if (stackInfo.getNumberOfFrames() == 0) {
						Msg.info(this, "t" + id.id + ".Stack is empty?");
					}
					else {
						DEBUG_STACK_FRAME frame = stackInfo.getFrame(0);
						Msg.info(this,
							String.format("t%d.Frame[0].io=%08x", id.id,
								frame.InstructionOffset.longValue()));
					}
				}
				catch (Exception e) {
					Msg.info(this, "Could not read t" + id.id + ".Frame[0].io: " + e);
				}
			}

			private void dumpPCViaRegsAPI() {
				DebugThreadId id = so.getCurrentThreadId();
				if (id.id == -1) {
					return;
				}
				try {
					Msg.info(this, String.format("t%d.rip=%s", id.id,
						registers.getValueByName("rip")));
				}
				catch (Exception e) {
					Msg.info(this, "Could not read t" + id.id + ".RIP: " + e);
				}
				try {
					Msg.info(this, String.format("t%d.eip=%s", id.id,
						registers.getValueByName("eip")));
				}
				catch (Exception e) {
					Msg.info(this, "Could not read t" + id.id + ".EIP: " + e);
				}
			}

			private void dumpCurrentThread() {
				dumpRegsViaDX();
				dumpFrame0ViaDX();
				dumpFrame0ViaK();
				dumpPCViaRegsAPI();
			}

			@Override
			public DebugStatus breakpoint(DebugBreakpoint bp) {
				super.breakpoint(bp);
				hit = true;
				Msg.info(this, "HIT!!!!");
				//dumpAllThreads();
				return DebugStatus.BREAK;
			}

			@Override
			public DebugStatus exception(DebugExceptionRecord64 exception, boolean firstChance) {
				DebugStatus status = super.exception(exception, firstChance);
				//dumpAllThreads();
				return status;
			}

			@Override
			public DebugStatus changeEngineState(BitmaskSet<ChangeEngineState> flags,
					long argument) {
				DebugStatus status = super.changeEngineState(flags, argument);
				if (flags.contains(ChangeEngineState.CURRENT_THREAD)) {
					return status;
				}
				if (!flags.contains(ChangeEngineState.EXECUTION_STATUS)) {
					return status;
				}
				if (DebugStatus.isInsideWait(argument)) {
					return status;
				}
				if (DebugStatus.fromArgument(argument) != DebugStatus.BREAK) {
					return status;
				}
				//dumpAllThreads(this::dumpRegsViaDX, false, false);
				//dumpAllThreads(this::dumpFrame0ViaDX, false, false);
				return status;
			}

			@Override
			public DebugStatus changeDebuggeeState(BitmaskSet<ChangeDebuggeeState> flags,
					long argument) {
				DebugStatus status = super.changeDebuggeeState(flags, argument);
				return status;
			}

			Map<Integer, ModelObject> frame0sByT = new HashMap<>();

			protected void cacheFrame0() {
				dumpAllThreads(() -> {
					int pid = so.getCurrentProcessSystemId();
					int tid = so.getCurrentThreadSystemId();
					String path = makePrefix(pid, tid) + ".Stack.Frames";
					ModelObject object = getObject(path);
					if (object == null) {
						Msg.error(this, "Could not get object: " + path);
					}
					else {
						frame0sByT.put(tid, object);
					}
				}, false, false);
			}

			@Override
			public DebugStatus createThread(DebugThreadInfo debugThreadInfo) {
				DebugStatus status = super.createThread(debugThreadInfo);
				cacheFrame0();
				return status;
			}

			@Override
			public DebugStatus createProcess(DebugProcessInfo debugProcessInfo) {
				DebugStatus status = super.createProcess(debugProcessInfo);
				cacheFrame0();
				return status;
			}

			private ModelObject getObject(String path) {
				List<String> parsed = PathUtils.parse(path);
				return util.getTerminalModelObject(parsed);
			}

			private String makePrefix(int pid, int tid) {
				return String.format("Debugger.Sessions[0x0].Processes[0x%x].Threads[0x%x]",
					pid, tid);
			}

			@Override
			public DebugStatus exitThread(int exitCode) {
				DebugStatus status = super.exitThread(exitCode);
				return status;
			}
		};

		try (ProcMaker maker = new ProcMaker(client, "C:\\Software\\Winmine__XP.exe")) {
			maker.start();

			client.setEventCallbacks(cb);

			DebugSymbols symbols = client.getSymbols();
			//assertEquals(1, symbols.getNumberLoadedModules());

			DebugModule modWinmine = symbols.getModuleByModuleName("winmine", 0);
			assertNotNull(modWinmine);
			long baseWinmine = modWinmine.getBase();
			assertEquals(0x01000000, baseWinmine);

			DebugBreakpoint bpt0 = control.addBreakpoint(BreakType.CODE);

			bpt0.setOffset(baseWinmine + 0x367a);
			bpt0.setFlags(BreakFlags.ENABLED);

			control.setExecutionStatus(DebugStatus.GO);

			while (!cb.hit) {
				Msg.info(this, "Not hit yet. Waiting");
				control.waitForEvent();
				Msg.info(this, "  ...");
			}
			Msg.info(this, "DONE");

			for (Map.Entry<Integer, ModelObject> ent : cb.frame0sByT.entrySet()) {
				Msg.info(this, String.format("IO-cached(0x%x): %s", ent.getKey(),
					ent.getValue()
							.getElements()
							.get(0)
							.getKeyValue("Attributes")
							.getKeyValue("InstructionOffset")));
			}
			cb.dumpFrame0ViaDX();

			BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
			while (true) {
				System.err.print(control.getPromptText());
				//control.prompt(BitmaskSet.of(), "Hello?>");
				String cmd = in.readLine();
				control.execute(cmd);
				if (control.getExecutionStatus().shouldWait) {
					control.waitForEvent();
				}
			}

			/**
			 * TODO: Didn't finish because the SetContext failed issue turned out to be mixed and/or
			 * broken DLLs.
			 */
		}
	}
}
