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
package ghidra.app.plugin.core;

import static org.junit.Assert.*;

import java.awt.Window;
import java.io.IOException;

import org.junit.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.analysis.*;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.disassembler.DisassemblerPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.test.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class AutoAnalysisWorkerTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private AddressFactory addrFactory;
	private Program program;
	private CodeBrowserPlugin cb;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		setupTool(tool);
	}

	private void setupTool(PluginTool tool) throws Exception {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		tool.addPlugin(AutoAnalysisPlugin.class.getName());
		tool.addPlugin(DisassemblerPlugin.class.getName());

		cb = env.getPlugin(CodeBrowserPlugin.class);
	}

	@After
	public void tearDown() {

		tool.cancelCurrentTask();
		waitForBusyTool(tool);

		env.dispose();
	}

	private void loadProgram(String programName) throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder(programName, true);
		builder.createMemory("test1", "0x1001000", 0x2000);
		builder.createEntryPoint("0x1001100", "entry");
		builder.addBytesMoveImmediate("0x1001100", (short) 0);
		builder.addBytesCall("0x1001102", "0x100110a");
		builder.addBytesReturn("0x1001106");
		builder.addBytesReturn("0x100110a");
		program = builder.getProgram();

		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		addrFactory = program.getAddressFactory();
	}

	private AnalysisWorker worker = new AnalysisWorker() {

		@Override
		public String getWorkerName() {
			return "testAutoAnalyzeDisableResume";
		}

		@Override
		public boolean analysisWorkerCallback(Program p, Object workerContext,
				TaskMonitor monitor) {

			// Can't invoke action since we are in background task here

			Options list = p.getOptions("TEST");
			assertTrue("Higher priorty analysis task failed to run first",
				list.getBoolean("p0", false));
			assertTrue("Lower priorty analysis task failed to run last",
				!list.getBoolean("p1", false));

			cb.goToField(addr("0x1001100"), "Operands", 0, 0);
			assertNull(p.getListing().getFunctionAt(addr("0x100110a")));

			DisassembleCommand cmd = new DisassembleCommand(addr("0x1001100"), null, true);
			cmd.applyTo(p, monitor);

			return true;
		}
	};

	/**
	 * Test running an AnalysisWorker from an ad hoc thread (i.e., Main)
	 * with events ignored by analysis at various priority levels.
	 * @throws Exception 
	 */
	@Test
	public void testDisableIgnoreResumeAdhocThreadWorkerInvocation() throws Exception {
		env.showTool();
		loadProgram("notepad_empty");

		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);

		schedule(mgr, new SetTestPropertyCommand("p0", 500), 0);
		schedule(mgr, new SetTestPropertyCommand("p1", 500), 10);

		try {
			mgr.scheduleWorker(worker, null, false, TaskMonitorAdapter.DUMMY_MONITOR);
		}
		catch (Exception e) {
			failWithException("Unexpected exception", e);
		}

		verifyProgramStateThenUndo(false);
	}

	/**
	 * Test running an AnalysisWorker from an adhoc thread (i.e., Main)
	 * with events used by analysis at various priority levels.
	 * @throws Exception 
	 */
	@Test
	public void testDisableResumeAdhocThreadWorkerInvocation() throws Exception {
		env.showTool();
		loadProgram("notepad_empty");

		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		schedule(mgr, new SetTestPropertyCommand("p0", 500), 0);
		schedule(mgr, new SetTestPropertyCommand("p1", 500), 10);

		try {
			mgr.scheduleWorker(worker, null, true, TaskMonitorAdapter.DUMMY_MONITOR);
		}
		catch (Exception e) {
			failWithException("Unexpected exception", e);
		}

		verifyProgramStateThenUndo(true);
	}

	/**
	 * Test running an AnalysisWorker from an analysis task thread
	 * with events ignored by analysis at various priority levels.
	 * @throws Exception 
	 */
	@Test
	public void testDisableIgnoreResumeAnalysisTaskWorkerInvocation() throws Exception {
		env.showTool();
		loadProgram("notepad_empty");

		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		schedule(mgr, new SetTestPropertyCommand("p0", 500), 0);
		schedule(mgr, new SetTestPropertyCommand("p1", 500), 10);

		WorkerBackgroundTestCmd cmd = new WorkerBackgroundTestCmd(false);
		schedule(mgr, cmd, 0);
		cmd.waitUntilFinished();

		if (cmd.error != null) {
			failWithException("Unexpected exception", cmd.error);
		}

		verifyProgramStateThenUndo(false);
	}

	/**
	 * Test running an AnalysisWorker from an analysis task thread
	 * with events used by analysis at various priority levels.
	 * @throws Exception 
	 */
	@Test
	public void testDisableResumeAnalysisTaskWorkerInvocation() throws Exception {
		env.showTool();
		loadProgram("notepad_empty");

		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		schedule(mgr, new SetTestPropertyCommand("p0", 500), 0);
		schedule(mgr, new SetTestPropertyCommand("p1", 500), 10);

		WorkerBackgroundTestCmd cmd = new WorkerBackgroundTestCmd(true);
		schedule(mgr, cmd, 0);
		cmd.waitUntilFinished();

		if (cmd.error != null) {
			failWithException("Unexpected exception", cmd.error);
		}

		verifyProgramStateThenUndo(true);
	}

	/**
	 * Test running an AnalysisWorker from a tool task thread
	 * with events ignored by analysis at various priority levels.
	 * @throws Exception 
	 */
	@Test
	public void testDisableIgnoreResumeToolTaskWorkerInvocation() throws Exception {
		env.showTool();
		loadProgram("notepad_empty");

		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		schedule(mgr, new SetTestPropertyCommand("p0", 500), 0);

		WorkerBackgroundTestCmd cmd = new WorkerBackgroundTestCmd(false);
		tool.scheduleFollowOnCommand(cmd, program);
		cmd.waitUntilFinished();

		schedule(mgr, new SetTestPropertyCommand("p1", 500), 10);

		if (cmd.error != null) {
			Assert.fail("Unexpected exception");
		}

		verifyProgramStateThenUndo(false);
	}

	/**
	 * Test running an AnalysisWorker from a tool task thread 
	 * with events used by analysis at various priority levels.
	 * @throws Exception 
	 */
	@Test
	public void testDisableResumeToolTaskWorkerInvocation() throws Exception {
		env.showTool();
		loadProgram("notepad_empty");

		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		schedule(mgr, new SetTestPropertyCommand("p0", 500), 0);

		WorkerBackgroundTestCmd cmd = new WorkerBackgroundTestCmd(true);
		tool.scheduleFollowOnCommand(cmd, program);
		cmd.waitUntilFinished();

		schedule(mgr, new SetTestPropertyCommand("p1", 500), 10);

		if (cmd.error != null) {
			Assert.fail("Unexpected exception");
		}

		verifyProgramStateThenUndo(true);
	}

	/**
	 * Test attempt to run an AnalysisWorker from swing thread
	 * @throws Exception 
	 */
	@Test
	public void testSwingThreadWorkerInvocation() throws Exception {
		env.showTool();
		loadProgram("notepad_empty");

		final AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		schedule(mgr, new SetTestPropertyCommand("p0", 500), 0);
		schedule(mgr, new SetTestPropertyCommand("p1", 500), 10);

		Runnable r = () -> {
			try {
				mgr.scheduleWorker(worker, null, false, TaskMonitorAdapter.DUMMY_MONITOR);
				Assert.fail("Expected UnsupportedOperationException");
			}
			catch (UnsupportedOperationException e1) {
				// expected
			}
			catch (Exception e2) {
				failWithException("Unexpected exception", e2);
			}
		};

		runSwing(r);
	}

	@Test
	public void testWorkerCancelled() throws Exception {
		env.showTool();
		loadProgram("notepad_empty");

		TaskMonitor myMonitor = new TaskMonitorAdapter();
		myMonitor.setCancelEnabled(true);

		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		try {
			mgr.scheduleWorker(new AnalysisWorker() {

				@Override
				public String getWorkerName() {
					return "CancelTest";
				}

				@Override
				public boolean analysisWorkerCallback(Program p, Object workerContext,
						TaskMonitor monitor) throws Exception, CancelledException {
					monitor.cancel();
					return false;
				}
			}, null, false, myMonitor);
			Assert.fail("CancelledException expected");
		}
		catch (CancelledException e) {
			// expected
		}
		catch (Exception e) {
			failWithException("Unexpected exception", e);
		}

		assertTrue(myMonitor.isCancelled());

	}

	@Test
	public void testBlockerCancelled() throws Exception {
		env.showTool();
		loadProgram("notepad_empty");

		TaskMonitor myMonitor = new TaskMonitorAdapter();
		myMonitor.setCancelEnabled(true);

		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		try {
			mgr.scheduleWorker(new AnalysisWorker() {

				@Override
				public String getWorkerName() {
					return "CancelTest";
				}

				@Override
				public boolean analysisWorkerCallback(Program p, Object workerContext,
						TaskMonitor monitor) throws Exception, CancelledException {

					// Click Cancel on modal blocker dialog 
					Window blockerDialog = waitForWindow("CancelTest");
					assertNotNull(blockerDialog);
					pressButtonByText(blockerDialog, "Cancel");

					Window confirmDialog = waitForWindow("Cancel?");
					assertNotNull(confirmDialog);
					pressButtonByText(confirmDialog, "Yes");
					waitForSwing();

					monitor.checkCanceled();

					Assert.fail("CancelledException expected");

					return false;
				}
			}, null, false, myMonitor);
			Assert.fail("CancelledException expected");
		}
		catch (CancelledException e) {
			// expected
		}
		catch (Exception e) {
			failWithException("Unexpected exception", e);
		}

		assertTrue(myMonitor.isCancelled());
	}

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}

	@SuppressWarnings("unused")
	private void closeProgram() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.closeProgram();
	}

	private void verifyProgramStateThenUndo(boolean functionShouldExist) {

		waitForBusyTool(tool);

		// verify that function does not get created when resumed
		cb.goToField(addr("0x1001100"), "Operands", 0, 0);
		Function f = program.getListing().getFunctionAt(addr("0x100110a"));
		if (functionShouldExist) {
			assertNotNull("Function should have been analyzed", f);
		}
		else {
			assertNull("Function should not have been analyzed", f);
		}

		Options list = program.getOptions("TEST");
		assertTrue("Lower priorty analysis task failed to complete after worker",
			list.getBoolean("p1", false));

		try {
			program.undo();
		}
		catch (IOException e) {
			Assert.fail("Unexpected exception");
		}
	}

	private void schedule(AutoAnalysisManager mgr, BackgroundCommand cmd, int priority) {
		invokeInstanceMethod("schedule", mgr, new Class[] { BackgroundCommand.class, int.class },
			new Object[] { cmd, priority });
	}

	private class SetTestPropertyCommand extends BackgroundCommand {
		private final String property;
		private final long delay;

		SetTestPropertyCommand(String property, long delay) {
			super("SetTestProperty", false, false, false);
			this.property = property;
			this.delay = delay;
		}

		@Override
		public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
			try {
				Thread.sleep(delay);
			}
			catch (InterruptedException e) {
				Assert.fail();// should never happen
			}

			Program p = (Program) obj;
			Options list = p.getOptions("TEST");
			list.setBoolean(property, true);
			return true;
		}
	}

	private class WorkerBackgroundTestCmd extends BackgroundCommand {

		private final boolean analyzeChanges;
		private volatile boolean isFinished = false;
		private Exception error;

		WorkerBackgroundTestCmd(boolean analyzeChanges) {
			super("WorkerBackgroundCmd", false, true, false);
			this.analyzeChanges = analyzeChanges;
		}

		@Override
		public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
			AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager((Program) obj);
			try {
				return mgr.scheduleWorker(worker, null, analyzeChanges,
					TaskMonitorAdapter.DUMMY_MONITOR);
			}
			catch (Exception e) {
				error = e;
			}
			finally {
				synchronized (this) {
					isFinished = true;
					notifyAll();
				}
			}
			return false;
		}

		synchronized void waitUntilFinished() {
			if (!isFinished) {
				try {
					wait();
				}
				catch (InterruptedException e) {
					// ignore
				}
			}
		}
	}

}
