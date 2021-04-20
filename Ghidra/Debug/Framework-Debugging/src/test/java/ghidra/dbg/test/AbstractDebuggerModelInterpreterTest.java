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

import static org.junit.Assert.*;
import static org.junit.Assume.assumeNotNull;
import static org.junit.Assume.assumeTrue;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Test;

import ghidra.async.AsyncReference;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.error.DebuggerModelTerminatingException;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.dbg.testutil.CatchOffThread;
import ghidra.util.Msg;

public abstract class AbstractDebuggerModelInterpreterTest extends AbstractDebuggerModelTest
		implements RequiresAttachSpecimen, RequiresLaunchSpecimen {

	/**
	 * Get the path of the expected result of {@link #findInterpreter()} for this test
	 * 
	 * @return the expected path
	 */
	public List<String> getExpectedInterpreterPath() {
		return null;
	}

	/**
	 * Get the CLI command to echo a string back
	 * 
	 * @param msg the message to echo
	 * @return the command
	 */
	protected abstract String getEchoCommand(String msg);

	/**
	 * If applicable, get the CLI command to terminate the session / model
	 * 
	 * @return the command
	 */
	protected abstract String getQuitCommand();

	/**
	 * Get the CLI command to attach to the {@link #dummy} process
	 * 
	 * @return the command
	 */
	protected abstract String getAttachCommand();

	/**
	 * Get the CLI command to detach from the given process
	 * 
	 * <p>
	 * Note that the given process should already be the current/active process of the interpreter,
	 * so the parameter may not be needed.
	 * 
	 * @param process the process to detach from, which should already be active
	 * @return the command
	 */
	protected abstract String getDetachCommand(TargetProcess process);

	/**
	 * Get the CLI command to kill the given process
	 * 
	 * <p>
	 * Note that the given process should already be the current/active process of the interpreter,
	 * so the parameter may not be needed.
	 * 
	 * @param process the process to kill, which should already be active
	 * @return the command
	 */
	protected abstract String getKillCommand(TargetProcess process);

	/**
	 * Perform an pre-test actions to ensure an interpreter exists where expected
	 * 
	 * <p>
	 * The model will have been built already. This method is invoked immediately preceding
	 * {@link #findInterpreter()}
	 * 
	 * @throws Throwable if anything goes wrong
	 */
	protected void ensureInterpreterAvailable() throws Throwable {
	}

	@Test
	public void testInterpreterIsWhereExpected() throws Throwable {
		List<String> expectedInterpreterPath = getExpectedInterpreterPath();
		assumeNotNull(expectedInterpreterPath);
		m.build();

		ensureInterpreterAvailable();
		TargetInterpreter interpreter = findInterpreter();
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

		ensureInterpreterAvailable();
		TargetInterpreter interpreter = findInterpreter();
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

		ensureInterpreterAvailable();
		TargetInterpreter interpreter = findInterpreter();
		runTestExecuteCapture(interpreter, cmd);
	}

	/**
	 * Test that the user quitting via the CLI properly terminates the model
	 * 
	 * @throws Throwable expected since the model will terminate
	 */
	@Test(expected = DebuggerModelTerminatingException.class)
	public void testExecuteQuit() throws Throwable {
		String cmd = getQuitCommand();
		assumeNotNull(cmd);
		m.build();

		ensureInterpreterAvailable();
		TargetInterpreter interpreter = findInterpreter();
		runTestExecute(interpreter, cmd);
	}

	protected TargetProcess runTestLaunchViaInterpreterShowsInProcessContainer(
			TargetInterpreter interpreter) throws Throwable {
		DebuggerTestSpecimen specimen = getLaunchSpecimen();
		assertNull(getProcessRunning(specimen, this));
		for (String line : specimen.getLaunchScript()) {
			waitOn(interpreter.execute(line));
		}
		return retryForProcessRunning(specimen, this);
	}

	protected void runTestKillViaInterpreter(TargetProcess process, TargetInterpreter interpreter)
			throws Throwable {
		waitOn(interpreter.execute(getKillCommand(process)));
		retryVoid(() -> {
			assertFalse(DebugModelConventions.isProcessAlive(process));
		}, List.of(AssertionError.class));
	}

	@Test
	public void testLaunchViaInterpreterShowsInProcessContainer() throws Throwable {
		assumeTrue(m.hasProcessContainer());
		m.build();

		ensureInterpreterAvailable();
		TargetInterpreter interpreter = findInterpreter();
		TargetProcess process = runTestLaunchViaInterpreterShowsInProcessContainer(interpreter);

		runTestKillViaInterpreter(process, interpreter);
	}

	protected TargetProcess runTestAttachViaInterpreterShowsInProcessContainer(
			TargetInterpreter interpreter) throws Throwable {
		DebuggerTestSpecimen specimen = getAttachSpecimen();
		assertNull(getProcessRunning(specimen, this));
		String cmd = getAttachCommand();
		waitOn(interpreter.execute(cmd));
		return retryForProcessRunning(specimen, this);
	}

	protected void runTestDetachViaInterpreter(TargetProcess process, TargetInterpreter interpreter)
			throws Throwable {
		waitOn(interpreter.execute(getDetachCommand(process)));
		retryVoid(() -> {
			assertFalse(DebugModelConventions.isProcessAlive(process));
		}, List.of(AssertionError.class));
	}

	@Test
	public void testAttachViaInterpreterShowsInProcessContainer() throws Throwable {
		DebuggerTestSpecimen specimen = getAttachSpecimen();
		assumeTrue(m.hasProcessContainer());
		m.build();
		dummy = specimen.runDummy();

		ensureInterpreterAvailable();
		TargetInterpreter interpreter = findInterpreter();
		TargetProcess process = runTestAttachViaInterpreterShowsInProcessContainer(interpreter);

		runTestDetachViaInterpreter(process, interpreter);
	}
}
