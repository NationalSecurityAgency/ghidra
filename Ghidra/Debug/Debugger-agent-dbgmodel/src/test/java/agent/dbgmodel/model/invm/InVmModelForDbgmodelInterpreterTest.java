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
package agent.dbgmodel.model.invm;

import static org.junit.Assert.assertNull;
import static org.junit.Assume.assumeTrue;

import java.util.List;

import org.junit.Ignore;
import org.junit.Test;

import agent.dbgeng.model.AbstractModelForDbgengInterpreterTest;
import agent.dbgeng.model.WindowsSpecimen;
import agent.dbgeng.model.iface2.DbgModelTargetProcess;
import ghidra.dbg.target.TargetInterpreter;
import ghidra.dbg.target.TargetProcess;
import ghidra.dbg.test.AbstractDebuggerModelTest;
import ghidra.dbg.test.ProvidesTargetViaLaunchSpecimen;
import ghidra.dbg.util.PathUtils;

public class InVmModelForDbgmodelInterpreterTest extends AbstractModelForDbgengInterpreterTest
		implements ProvidesTargetViaLaunchSpecimen {
	@Override
	public ModelHost modelHost() throws Throwable {
		return new InVmDbgmodelModelHost();
	}

	@Override
	public AbstractDebuggerModelTest getTest() {
		return this;
	}

	@Override
	protected List<String> seedPath() {
		return PathUtils.parse("");
	}

	@Override
	public List<String> getExpectedInterpreterPath() {
		return PathUtils.parse("Sessions[0x0]");
	}

	@Override
	protected void ensureInterpreterAvailable() throws Throwable {
		obtainTarget();
	}

	@Override
	@Ignore
	@Test
	public void testAttachViaInterpreterShowsInProcessContainer() throws Throwable {
		super.testAttachViaInterpreterShowsInProcessContainer();
	}

	@Override
	@Test
	public void testLaunchViaInterpreterShowsInProcessContainer() throws Throwable {
		assumeTrue(m.hasProcessContainer());
		m.build();
		DbgModelTargetProcess initialTarget = (DbgModelTargetProcess) obtainTarget();

		DebuggerTestSpecimen specimen = WindowsSpecimen.NOTEPAD;
		assertNull(getProcessRunning(specimen, this));
		TargetInterpreter interpreter = findInterpreter();
		for (String line : specimen.getLaunchScript()) {
			waitOn(interpreter.execute(line));
		}
		TargetProcess process = retryForProcessRunning(specimen, this);
		initialTarget.detach();

		runTestKillViaInterpreter(process, interpreter);
	}

}
