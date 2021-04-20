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

import java.util.List;
import java.util.Map;

import org.junit.Ignore;
import org.junit.Test;

import agent.dbgeng.model.AbstractModelForDbgengX64RegistersTest;
import ghidra.dbg.util.PathUtils;

public class InVmModelForDbgmodelX64RegistersTest extends AbstractModelForDbgengX64RegistersTest {

	public final Map<String, byte[]> REG_VALSX = Map.ofEntries(
		Map.entry("rax", arr("0123456789abcdef")),
		Map.entry("rdx", arr("fedcba9876543210")));

	@Override
	public ModelHost modelHost() throws Throwable {
		return new InVmDbgmodelModelHost();
	}

	@Override
	public boolean isRegisterBankAlsoContainer() {
		return false;
	}

	@Override
	public List<String> getExpectedRegisterBankPath(List<String> threadPath) {
		return PathUtils.extend(threadPath, List.of("Registers", "User"));
	}

	@Override
	public Map<String, byte[]> getRegisterWrites() {
		return REG_VALSX;
	}

	@Override
	@Ignore
	@Test
	public void testRegistersHaveExpectedSizes() throws Throwable {
		super.testRegistersHaveExpectedSizes();
	}
}
