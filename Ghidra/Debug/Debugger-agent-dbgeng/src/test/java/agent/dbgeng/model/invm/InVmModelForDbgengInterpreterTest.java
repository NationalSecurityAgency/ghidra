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
package agent.dbgeng.model.invm;

import org.junit.Ignore;
import org.junit.Test;

import agent.dbgeng.model.AbstractModelForDbgengInterpreterTest;
import ghidra.dbg.error.DebuggerModelTerminatingException;

public class InVmModelForDbgengInterpreterTest extends AbstractModelForDbgengInterpreterTest {
	@Override
	public ModelHost modelHost() throws Throwable {
		return new InVmDbgengModelHost();
	}

	@Override
	@Ignore
	@Test
	public void testAttachViaInterpreterShowsInProcessContainer() throws Throwable {
		super.testAttachViaInterpreterShowsInProcessContainer();
	}

	@Override
	@Ignore
	@Test(expected = DebuggerModelTerminatingException.class)
	public void testExecuteQuit() throws Throwable {
		// Different behavior for dbg clients vice gdb
	}

}
