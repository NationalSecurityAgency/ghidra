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
package agent.gdb.model.invm;

import static org.junit.Assume.assumeFalse;

import org.junit.Ignore;
import org.junit.Test;

import agent.gdb.model.AbstractModelForGdbInferiorAttacherTest;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

public class InVmModelForGdbInferiorAttacherTest extends AbstractModelForGdbInferiorAttacherTest {
	@Override
	public ModelHost modelHost() throws Throwable {
		return new InVmGdbModelHost();
	}

	@Override
	@Ignore("Some hang. I don't know why")
	public void testAttachableContainerIsWhereExpected() throws Throwable {
		// nop
	}

	/**
	 * Run a dummy process without a tty. It seems when GDB (I tested with 8.0.1) attaches to such a
	 * process, it is unable to interrupt it from the opposite interpreter that resumed it.
	 */
	@Test
	@Ignore("Not a real test")
	public void testRunADummy() throws Throwable {
		assumeFalse(SystemUtilities.isInTestingBatchMode());

		DebuggerTestSpecimen specimen = getAttachSpecimen();
		dummy = specimen.runDummy();

		Msg.info(this, "Dummy pid: " + dummy.pid);
		dummy.process.waitFor();
		Msg.info(this, "Dummy terminated");
	}
}
