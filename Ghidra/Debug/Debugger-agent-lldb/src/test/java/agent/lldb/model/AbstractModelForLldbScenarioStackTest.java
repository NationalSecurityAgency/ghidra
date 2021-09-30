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
package agent.lldb.model;

import static org.junit.Assert.assertEquals;

import java.util.*;
import java.util.Map.Entry;

import ghidra.dbg.target.*;
import ghidra.dbg.test.AbstractDebuggerModelScenarioStackTest;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;

public abstract class AbstractModelForLldbScenarioStackTest
		extends AbstractDebuggerModelScenarioStackTest {
	protected static List<String> expectedSymbols =
		List.of("break_here", "funcC", "funcB", "funcA");
	protected NavigableMap<Address, String> symbolsByAddress = new TreeMap<>();

	@Override
	protected MacOSSpecimen getSpecimen() {
		return MacOSSpecimen.STACK;
	}

	@Override
	protected String getBreakpointExpression() {
		return "break_here";
	}

	@Override
	protected void postLaunch(TargetProcess process) throws Throwable {
		TargetObject session = process.getParent().getParent();
		TargetModuleContainer modules = m.find(TargetModuleContainer.class, session.getPath());
		// NB. NEVER is recommended resync mode for modules container
		// It's not guaranteed to come before process is alive, though
		TargetModule binMod = (TargetModule) waitOn(m.getAddedWaiter()
				.wait(PathUtils.index(modules.getPath(), getSpecimen().getBinModuleKey())));

		// NB. this heuristic assumes all function bodies are contiguous in memory
		TargetSymbolNamespace symbols = m.find(TargetSymbolNamespace.class, binMod.getPath());
		// NB. ONCE is recommended resync mode for module symbols
		for (Entry<String, ? extends TargetObject> entry : waitOn(symbols.fetchElements())
				.entrySet()) {
			symbolsByAddress.put(entry.getValue().as(TargetSymbol.class).getValue(),
				entry.getKey());
		}
	}

	@Override
	protected void validateFramePC(int index, Address pc) {
		assertEquals(expectedSymbols.get(index), symbolsByAddress.floorEntry(pc).getValue());
	}
}
