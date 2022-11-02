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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Map.Entry;

import org.junit.Ignore;
import org.junit.Test;

import agent.frida.model.iface2.FridaModelTargetProcess;
import agent.frida.model.impl.FridaModelTargetThreadContainerImpl;

import java.util.NavigableMap;
import java.util.TreeMap;

import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.DebugModelConventions.AsyncState;
import ghidra.dbg.target.TargetExecutionStateful;
import ghidra.dbg.target.TargetLauncher;
import ghidra.dbg.target.TargetModule;
import ghidra.dbg.target.TargetModuleContainer;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetProcess;
import ghidra.dbg.target.TargetStack;
import ghidra.dbg.target.TargetStackFrame;
import ghidra.dbg.target.TargetSymbol;
import ghidra.dbg.target.TargetSymbolNamespace;
import ghidra.dbg.test.AbstractDebuggerModelScenarioStackTest;
import ghidra.dbg.util.PathMatcher;
import ghidra.dbg.util.PathPattern;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;

public abstract class AbstractModelForFridaScenarioStackTest
		extends AbstractDebuggerModelScenarioStackTest {
	protected static List<String> expectedSymbols =
		List.of("_end", "_end", "_end", "_end");
	protected NavigableMap<Address, String> symbolsByAddress = new TreeMap<>();

	@Override
	protected FridaLinuxSpecimen getSpecimen() {
		return FridaLinuxSpecimen.SPIN_STRIPPED;
	}

	@Override
	//@Ignore // Fails for distributed version
	@Ignore
	@Test
	public void testScenario() throws Throwable {
		DebuggerTestSpecimen specimen = getSpecimen();
		m.build();

		Msg.debug(this, "Launching " + specimen);
		TargetLauncher launcher = findLauncher();
		waitOn(launcher.launch(specimen.getLauncherArgs()));
		Msg.debug(this, "  Done launching");
		TargetProcess process = retryForProcessRunning(specimen, this);
		postLaunch(process);

		assertTrue(DebugModelConventions.isProcessAlive(process));
		AsyncState state =
			new AsyncState(m.suitable(TargetExecutionStateful.class, process.getPath()));

		assertTrue(state.get().isAlive());

		FridaModelTargetProcess fproc = (FridaModelTargetProcess) process;
		waitOn(fproc.resume());
		FridaModelTargetThreadContainerImpl threads = (FridaModelTargetThreadContainerImpl) fproc.getCachedAttribute("Threads");
		waitOn(threads.fetchElements());

		TargetStack stack = findStack(process.getPath());
		PathMatcher matcher = stack.getSchema().searchFor(TargetStackFrame.class, true);
		PathPattern pattern = matcher.getSingletonPattern();
		assertNotNull("Frames are not clearly indexable", pattern);
		assertEquals("Frames are not clearly indexable", 1, pattern.countWildcards());
		// Sort by path should present them innermost to outermost
		List<TargetStackFrame> frames = retry(() -> {
			List<TargetStackFrame> result =
				List.copyOf(m.findAll(TargetStackFrame.class, stack.getPath(), true).values());
			assertTrue("Fewer than 4 frames", result.size() > 4);
			return result;
		}, List.of(AssertionError.class));
		for (int i = 0; i < 4; i++) {
			TargetStackFrame f = frames.get(i);
			validateFramePC(i, f.getProgramCounter());
		}

	}

	@Override
	protected void postLaunch(TargetProcess process) throws Throwable {
		TargetObject session = process.getParent().getParent();
		TargetModuleContainer modules = m.find(TargetModuleContainer.class, session.getPath());
		// NB. NEVER is recommended resync mode for modules container
		// It's not guaranteed to come before process is alive, though
		TargetModule binMod = (TargetModule) waitOn(m.getAddedWaiter()
				.wait(PathUtils.index(modules.getPath(), getSpecimen().getShortName())));

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
	protected TargetStack findStack(List<String> seedPath) throws Throwable {
		return m.findAny(TargetStack.class, seedPath);
	}
	
	@Override
	protected void validateFramePC(int index, Address pc) {
		assertEquals(expectedSymbols.get(index), symbolsByAddress.floorEntry(pc).getValue());
	}
	
	@Override
	protected String getBreakpointExpression() {
		return null;
	}

}
