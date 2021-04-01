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

import java.util.Map;

import ghidra.dbg.test.AbstractDebuggerModelTest.DebuggerTestSpecimen;

public abstract class AbstractDebuggerModelEnvironmentTest {
	protected void doTestLaunchEnvironment(DebuggerTestSpecimen specimen,
			Map<String, String> expectedEnvironment) {
		// TODO: Check that the environment is as expected before PROCESS_CREATED is emitted
		// For models without event scope, before TargetProcess gets added.
	}
}
