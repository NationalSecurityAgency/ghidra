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
package ghidra.dbg.test;

import static ghidra.lifecycle.Unfinished.*;
import static org.junit.Assert.*;
import static org.junit.Assume.*;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Ignore;
import org.junit.Test;

import ghidra.async.AsyncReference;
import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.error.DebuggerModelTerminatingException;
import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.dbg.target.TargetInterpreter;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.testutil.CatchOffThread;
import ghidra.util.Msg;

public abstract class AbstractDebuggerModelInterpreterTest extends AbstractDebuggerModelTest
		implements RequiresAttachSpecimen, RequiresLaunchSpecimen {

	public List<String> getExpectedInterpreterPath() {
		return null;
	}

	protected abstract String getEchoCommand(String msg);

	protected abstract String getQuitCommand();

	/**
	 * Get the CLI command to attach to the {@link #dummy} process
	 * 
	 * @return the command
	 */
	protected abstract String getAttachCommand();

	@Test
	public void testInterpreterIsWhereExpected() throws Throwable {
		List<String> expectedInterpreterPath = getExpectedInterpreterPath();
		assumeNotNull(expectedInterpreterPath);
		m.build();

		TargetInterpreter interpreter = m.find(TargetInterpreter.class, List.of());
		assertEquals(expectedInterpreterPath, interpreter.getPath());
	}

	protected void runTestExecute(TargetInterpreter interpreter, String cmd) throws Throwable {
		AsyncReference<String, Void> lastOut = new AsyncReference<>();
		DebuggerModelListener l = new DebuggerModelListener() {
			@Override
			public void consoleOutput(TargetObject interpreter, Channel channel, byte[] out) {
				String str = new String(out);
				Msg.debug(this, "Got " + channel + " output: " + str);
				for (String line : str.split("\n")) {
					lastOut.set(line.trim(), null);
				}
			}
		};
		interpreter.addListener(l);
		waitAcc(interpreter);
		waitOn(interpreter.execute(cmd));
		waitOn(lastOut.waitValue("test"));
	}

	@Test
	public void testExecute() throws Throwable {
		String cmd = getEchoCommand("test");
		assumeNotNull(cmd);
		m.build();

		TargetInterpreter interpreter = m.find(TargetInterpreter.class, List.of());
		runTestExecute(interpreter, cmd);
	}

	protected void runTestExecuteCapture(TargetInterpreter interpreter, String cmd)
			throws Throwable {
		waitAcc(interpreter);
		try (CatchOffThread off = new CatchOffThread()) {
			DebuggerModelListener l = new DebuggerModelListener() {
				@Override
				public void consoleOutput(TargetObject interpreter, Channel channel, byte[] out) {
					String str = new String(out);
					Msg.debug(this, "Got " + channel + " output: " + str);
					if (!str.contains("test")) {
						return;
					}
					off.catching(() -> fail("Unexpected output:" + str));
				}
			};
			interpreter.addListener(l);
			waitAcc(interpreter);
			String out = waitOn(interpreter.executeCapture(cmd));
			// Not the greatest, but allow extra lines
			List<String> lines =
				Stream.of(out.split("\n")).map(s -> s.trim()).collect(Collectors.toList());
			assertTrue(lines.contains("test"));
		}
	}

	@Test
	public void testExecuteCapture() throws Throwable {
		String cmd = getEchoCommand("test");
		assumeNotNull(cmd);
		m.build();

		TargetInterpreter interpreter = m.find(TargetInterpreter.class, List.of());
		runTestExecuteCapture(interpreter, cmd);
	}

	@Test(expected = DebuggerModelTerminatingException.class)
	public void testExecuteQuit() throws Throwable {
		String cmd = getQuitCommand();
		assumeNotNull(cmd);
		m.build();

		TargetInterpreter interpreter = m.find(TargetInterpreter.class, List.of());
		runTestExecute(interpreter, cmd);
	}

	@Test
	@Ignore
	public void testFocusIsSynced() throws Throwable {
		TODO();
	}

	@Test
	@Ignore
	public void testBreakpointsAreSynced() throws Throwable {
		TODO();
		// TODO: Place different kinds
		// TODO: Enable/disable
		// TODO: Delete (spec vs. loc?)
	}

	protected void runTestLaunchViaInterpreterShowsInProcessContainer(TargetInterpreter interpreter,
			TargetObject container) throws Throwable {
		DebuggerTestSpecimen specimen = getLaunchSpecimen();
		assertNull(getProcessRunning(container, specimen, this));
		for (String line : specimen.getLaunchScript()) {
			waitOn(interpreter.execute(line));
		}
		retryForProcessRunning(container, specimen, this);
	}

	@Test
	public void testLaunchViaInterpreterShowsInProcessContainer() throws Throwable {
		assumeTrue(m.hasProcessContainer());
		m.build();

		TargetInterpreter interpreter = findInterpreter();
		TargetObject container = findProcessContainer();
		assertNotNull("No process container", container);
		runTestLaunchViaInterpreterShowsInProcessContainer(interpreter, container);
	}

	protected void runTestAttachViaInterpreterShowsInProcessContainer(TargetInterpreter interpreter,
			TargetObject container) throws Throwable {
		DebuggerTestSpecimen specimen = getAttachSpecimen();
		assertNull(getProcessRunning(container, specimen, this));
		String cmd = getAttachCommand();
		waitOn(interpreter.execute(cmd));
		retryForProcessRunning(container, specimen, this);
	}

	@Test
	public void testAttachViaInterpreterShowsInProcessContainer() throws Throwable {
		DebuggerTestSpecimen specimen = getAttachSpecimen();
		assumeTrue(m.hasProcessContainer());
		m.build();
		dummy = specimen.runDummy();

		TargetInterpreter interpreter = findInterpreter();
		TargetObject container = findProcessContainer();
		assertNotNull("No process container", container);
		runTestAttachViaInterpreterShowsInProcessContainer(interpreter, container);
	}
}
