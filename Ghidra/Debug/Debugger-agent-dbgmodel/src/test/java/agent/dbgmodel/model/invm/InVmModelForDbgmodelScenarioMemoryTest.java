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

import java.util.*;

import agent.dbgeng.model.AbstractModelForDbgengScenarioMemoryTest;
import ghidra.dbg.target.TargetModule;
import ghidra.dbg.target.TargetProcess;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;

public class InVmModelForDbgmodelScenarioMemoryTest
		extends AbstractModelForDbgengScenarioMemoryTest {
	@Override
	public ModelHost modelHost() throws Throwable {
		return new InVmDbgmodelModelHost();
	}

	@Override
	protected Address getAddressToWrite(TargetProcess process) throws Throwable {
		// It seems this is the only test case that exercises module symbols.
		List<String> modulePath = PathUtils.extend(process.getPath(),
			PathUtils.parse("Modules"));
		Map<List<String>, TargetModule> modules = m.findAll(TargetModule.class, modulePath, true);
		Collection<TargetModule> values = modules.values();
		TargetModule test = (TargetModule) values.toArray()[0];
		AddressRange range =
			(AddressRange) test.fetchAttribute(TargetModule.RANGE_ATTRIBUTE_NAME).get();
		return range.getMinAddress().add(0x15000);
	}
}
