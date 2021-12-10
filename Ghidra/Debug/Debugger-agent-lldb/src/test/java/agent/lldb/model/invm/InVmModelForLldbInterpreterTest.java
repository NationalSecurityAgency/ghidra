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
package agent.lldb.model.invm;

import org.junit.Ignore;
import org.junit.Test;

import agent.lldb.model.AbstractModelForLldbInterpreterTest;
import ghidra.dbg.test.ProvidesTargetViaLaunchSpecimen;

public class InVmModelForLldbInterpreterTest extends AbstractModelForLldbInterpreterTest 
		implements ProvidesTargetViaLaunchSpecimen {
	@Override
	public ModelHost modelHost() throws Throwable {
		return new InVmLldbModelHost();
	}

	// Not sure what the behavior for these two should be...
	//  "file target" will change the process and this isn't handled
	//  also getLaunchScript in MacOSSpecimen is currently wrong
	@Override
	@Ignore
	@Test
	public void testLaunchViaInterpreterShowsInProcessContainer() throws Throwable {
		super.testLaunchViaInterpreterShowsInProcessContainer();
	}

	@Override
	@Ignore
	@Test
	public void testAttachViaInterpreterShowsInProcessContainer() throws Throwable {
		super.testAttachViaInterpreterShowsInProcessContainer();
	}

	// "quit" does not have the desired behavior
	@Override
	@Ignore
	@Test
	public void testExecuteQuit() throws Throwable {
		super.testExecuteQuit();
	}

	@Override
	@Ignore
	@Test
	public void testInterpreterIsWhereExpected() throws Throwable {
		super.testInterpreterIsWhereExpected();
	}

}

