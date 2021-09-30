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
package agent.lldb.model;

import static org.junit.Assert.*;

import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.After;

import agent.lldb.model.iface1.LldbModelTargetKillable;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.test.AbstractDebuggerModelAttacherTest;
import ghidra.dbg.util.PathUtils;
import ghidra.util.Msg;

public abstract class AbstractModelForLldbRootAttacherTest
		extends AbstractDebuggerModelAttacherTest {

	@Override
	public List<String> getExpectedAttachableContainerPath() {
		return List.of("Available");
	}

	@Override
	public List<String> getExpectedAttacherPath() {
		return PathUtils.parse("");
	}

	@Override
	public DebuggerTestSpecimen getAttachSpecimen() {
		return MacOSSpecimen.SPIN;
	}

	@Override
	public TargetParameterMap getExpectedAttachParameters() {
		return null; // TODO
	}

	@Override
	public void assertEnvironment(TargetEnvironment environment) {
		assertTrue(environment.getArchitecture().startsWith("x86_64"));
		//assertTrue(environment.getOperatingSystem().startsWith("macos"));
		assertEquals("little", environment.getEndian());
		assertTrue(environment.getDebugger().toLowerCase().contains("lldb"));
	}

	@Override
	@After
	public void tearDownDebuggerModelTest() throws Throwable {
		/**
		 * NB. Model has to be closed before dummy. If dummy is suspended by a debugger, terminating
		 * it, even forcibly, may fail.
		 */
		if (m != null) {
			m.close();
		}
		if (dummy != null) {
			if (!dummy.process.destroyForcibly().waitFor(1000, TimeUnit.MILLISECONDS)) {
				Msg.error(this, "Could not terminate process " + dummy.process.pid());
				//throw new TimeoutException("Could not terminate process " + pid);
			}
			//dummy.close();
		}
	}

	@Override
	protected void runTestKill(DebuggerTestSpecimen specimen)
			throws Throwable {
		TargetProcess process = retryForProcessRunning(specimen, this);
		LldbModelTargetKillable killable =
			(LldbModelTargetKillable) m.suitable(TargetKillable.class, process.getPath());
		waitAcc(killable);
		waitOn(killable.destroy());
		retryVoid(() -> assertFalse(DebugModelConventions.isProcessAlive(process)),
			List.of(AssertionError.class));
	}
}
