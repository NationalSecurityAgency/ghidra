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
package ghidra.dbg.jdi.model;

import java.util.HashMap;
import java.util.Map;

import org.junit.*;

import generic.Unique;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.jdi.JdiExperimentsTest;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.testutil.DebuggerModelTestUtils;
import ghidra.dbg.util.PathUtils;
import ghidra.util.Msg;

public class JdiModelTest implements DebuggerModelTestUtils {
	DebuggerObjectModel model;

	@Before
	public void setUp() {
		model = new JdiModelImpl();
	}

	@After
	public void tearDown() {
		model.close();
	}

	@Test
	public void testConnectorParameterReflection() throws Throwable {
		for (TargetObject conn : waitOn(model.fetchObjectElements("Connectors")).values()) {
			TargetLauncher launcher = conn.as(TargetLauncher.class);
			Msg.info(this, "Launcher: " + launcher);
			for (ParameterDescription<?> desc : launcher.getParameters().values()) {
				Msg.info(this, "  " + desc);
			}
		}
	}

	@Test
	@Ignore("TODO") // Not important
	public void testCommandLineLauncher() throws Throwable {
		TargetLauncher launcher = (TargetLauncher) waitOn(
			model.fetchModelObject(PathUtils.parse("Connectors[com.sun.jdi.CommandLineLaunch]")));
		Map<String, Object> parameters = new HashMap<>();
		parameters.put("main", JdiExperimentsTest.HelloWorld.class.getName());
		parameters.put("quote", "\"");
		parameters.put("vmexec", "java");
		waitOn(launcher.launch(parameters));

		TargetObject vm =
			Unique.assertOne(waitOn(model.fetchObjectElements("VirtualMachines")).values());
		waitOn(vm.as(TargetKillable.class).kill());
	}
}
