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
package agent.dbgeng.model;

import static org.junit.Assert.assertEquals;

import java.util.List;
import java.util.Objects;

import agent.dbgeng.model.impl.DbgModelTargetProcessImpl;
import ghidra.dbg.target.*;
import ghidra.dbg.test.AbstractDebuggerModelScenarioMemoryTest;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;

public abstract class AbstractModelForDbgengScenarioMemoryTest
		extends AbstractDebuggerModelScenarioMemoryTest {

	@Override
	protected WindowsSpecimen getSpecimen() {
		return WindowsSpecimen.PRINT;
	}

	protected String getSymbolName() {
		return "overwrite";
	}

	@Override
	protected Address getAddressToWrite(TargetProcess process) throws Throwable {
		// It seems this is the only test case that exercises module symbols.
		List<String> modulePath = PathUtils.extend(process.getPath(),
			PathUtils.parse("Modules[" + getSpecimen().getBinModuleKey() + "]"));
		TargetObject container =
			Objects.requireNonNull(m.findContainer(TargetSymbol.class, modulePath));
		TargetSymbol symbol =
			waitOn(container.fetchElements()).get(getSymbolName()).as(TargetSymbol.class);
		return symbol.getValue();
	}

	@Override
	protected byte[] getBytesToWrite() {
		return "Speak".getBytes();
	}

	@Override
	protected byte[] getExpectedBytes() {
		return "Speak, World!".getBytes();
	}

	@Override
	protected void verifyExpectedEffect(TargetProcess process) throws Throwable {
		// TODO: Should (optional) exitCode be standardized on all models?
		retryVoid(() -> {
			long status = process.getTypedAttributeNowByName(
				DbgModelTargetProcessImpl.EXIT_CODE_ATTRIBUTE_NAME, Long.class, 0L);
			assertEquals('S', status);
		}, List.of(AssertionError.class));
	}
}
