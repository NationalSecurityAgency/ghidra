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
package agent.frida.model.invm;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import agent.frida.model.AbstractModelForFridaInterpreterTest;
import generic.test.category.NightlyCategory;
import ghidra.dbg.test.ProvidesTargetViaLaunchSpecimen;

@Category(NightlyCategory.class) // this may actually be an @PortSensitive test
public class InVmModelForFridaInterpreterTest extends AbstractModelForFridaInterpreterTest
		implements ProvidesTargetViaLaunchSpecimen {
	@Override
	public ModelHost modelHost() throws Throwable {
		return new InVmFridaModelHost();
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
