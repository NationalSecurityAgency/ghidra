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
package agent.frida.model;

import java.util.Map;

import org.junit.Ignore;
import org.junit.Test;

import ghidra.dbg.test.AbstractDebuggerModelFactoryTest;

public abstract class AbstractModelForFridaFactoryTest extends AbstractDebuggerModelFactoryTest {
	@Override
	protected Map<String, Object> getFailingFactoryOptions() {
		return Map.ofEntries();
	}

	@Override
	@Ignore
	@Test
	public void testBuildAndClose() throws Throwable {
		// Disabled as of 220609
	}

	@Override
	@Ignore
	@Test
	public void testBuildFailingOptionsErr() throws Throwable {
		// Disabled as of 220609
	}

	@Override
	@Ignore
	@Test
	public void testPing() throws Throwable {
		// Disabled as of 220609
	}

	@Override
	@Ignore
	@Test
	public void testWaitRootAccess() throws Throwable {
		// Disabled as of 220609
	}

	@Override
	@Ignore
	@Test
	public void testHasNonEnumerableRootSchema() throws Throwable {
		// Disabled as of 220609
	}

	@Override
	@Ignore
	@Test
	public void testNonExistentPathGivesNull() throws Throwable {
		// Disabled as of 220609
	}

}
