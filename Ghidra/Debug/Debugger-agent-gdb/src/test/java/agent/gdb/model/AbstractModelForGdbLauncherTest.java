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
package agent.gdb.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Ignore;
import org.junit.Test;

import agent.gdb.model.impl.GdbModelTargetInferior;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.test.AbstractDebuggerModelLauncherTest;

public abstract class AbstractModelForGdbLauncherTest extends AbstractDebuggerModelLauncherTest {

	@Override
	public DebuggerTestSpecimen getLaunchSpecimen() {
		return GdbLinuxSpecimen.PRINT;
	}

	@Override
	public TargetParameterMap getExpectedLauncherParameters() {
		return GdbModelTargetInferior.PARAMETERS;
	}

	@Override
	public void assertEnvironment(TargetEnvironment environment) {
		// TODO: This test won't always be on amd64 Linux, no?
		assertEquals("i386:x86-64", environment.getArchitecture());
		assertEquals("GNU/Linux", environment.getOperatingSystem());
		assertEquals("little", environment.getEndian());
		assertTrue(environment.getDebugger().toLowerCase().contains("gdb"));
	}

	protected DebuggerTestSpecimen getLaunchStrippedSpecimen() {
		return GdbLinuxSpecimen.SPIN_STRIPPED;
	}

	/**
	 * Test a target which runs indefinitely, and for which GDB cannot get the temporary breakpoint
	 * on main.
	 */
	@Test
	@Ignore
	public void testLaunchStrippedThenInterrupt() throws Throwable {
		m.build();

		ProcessCreatedDebugModelListener listener = new ProcessCreatedDebugModelListener();
		// NB. I've intentionally omitted the reorderer here. The model should get it right.
		m.getModel().addModelListener(listener);

		DebuggerTestSpecimen specimen = getLaunchStrippedSpecimen();
		TargetLauncher launcher = findLauncher();
		waitAcc(launcher);
		waitOn(launcher.launch(specimen.getLauncherArgs()));
		//System.err.println("Launched");

		/**
		 * For the moment, we're stuck having to wait for the initial break in GDB before we
		 * announce that the target is RUNNING, because we depend on the environment being correct
		 * *before* that announcement. For launch, we can resolve the issue, because we can refresh
		 * the environment between "file" and "start". However, for attach, we're still hosed. I
		 * don't care to try to distinguish the two cases, because that's a lot of work, and still
		 * only a partial fix.
		 * 
		 * Thus, we will not observe state=RUNNING until after we successfully interrupt the target.
		 * This test still suffices to address the interrupt problem, but I don't know any way to
		 * fix the state reporting problem until we fix the record-depends-on-language-mapping
		 * issue, which is still some time away.
		 */
		TargetInterruptible interruptible =
			m.suitable(TargetInterruptible.class, launcher.getPath());
		Thread.sleep(1000); // HACK
		waitOn(interruptible.interrupt());
		//System.err.println("Interrupted");

		waitOn(listener.observedCreated);
		//System.err.println("Observed");
	}
}
