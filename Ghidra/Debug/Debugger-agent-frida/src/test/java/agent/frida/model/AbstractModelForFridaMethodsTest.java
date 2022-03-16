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

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.NavigableMap;
import java.util.TreeMap;

import org.junit.Test;

import agent.frida.manager.FridaEventsListenerAdapter;
import agent.frida.model.iface2.FridaModelTargetProcess;
import agent.frida.model.iface2.FridaModelTargetSymbol;
import agent.frida.model.impl.FridaModelTargetMemoryContainerImpl;
import agent.frida.model.impl.FridaModelTargetThreadContainerImpl;
import agent.frida.model.impl.FridaModelTargetThreadImpl;
import agent.frida.model.methods.FridaModelTargetFunctionInterceptorImpl;
import agent.frida.model.methods.FridaModelTargetMemoryScanImpl;
import agent.frida.model.methods.FridaModelTargetMemoryWatchImpl;
import agent.frida.model.methods.FridaModelTargetThreadStalkImpl;
import generic.jar.ResourceFile;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.DebugModelConventions.AsyncState;
import ghidra.dbg.target.TargetExecutionStateful;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetKillable;
import ghidra.dbg.target.TargetLauncher;
import ghidra.dbg.target.TargetModule;
import ghidra.dbg.target.TargetModuleContainer;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetProcess;
import ghidra.dbg.target.TargetResumable;
import ghidra.dbg.target.TargetSymbol;
import ghidra.dbg.target.TargetSymbolNamespace;
import ghidra.dbg.test.AbstractDebuggerModelTest;
import ghidra.dbg.test.RequiresLaunchSpecimen;
import ghidra.dbg.util.PathUtils;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;

public abstract class AbstractModelForFridaMethodsTest extends AbstractDebuggerModelTest
		implements RequiresLaunchSpecimen {

	protected NavigableMap<String, TargetSymbol> symbolsByKey = new TreeMap<>();

	@Override
	public FridaLinuxSpecimen getLaunchSpecimen() {
		return FridaLinuxSpecimen.PRINT;
	}
	public FridaLinuxSpecimen getPrintSpecimen() {
		return FridaLinuxSpecimen.PRINT;
	}
	public FridaLinuxSpecimen getStackSpecimen() {
		return FridaLinuxSpecimen.STACK;
	}
	public FridaLinuxSpecimen getSpinSpecimen() {
		return FridaLinuxSpecimen.SPIN_STRIPPED;
	}

	protected TargetProcess runTestLaunch(DebuggerTestSpecimen specimen, TargetLauncher launcher) throws Throwable {
		waitAcc(launcher);
		waitOn(launcher.launch(specimen.getLauncherArgs()));

		TargetProcess process = retryForProcessRunning(specimen, this);
		TargetObject session = process.getParent().getParent();
		TargetModuleContainer modules = m.find(TargetModuleContainer.class, session.getPath());
		TargetModule binMod = (TargetModule) waitOn(m.getAddedWaiter()
				.wait(PathUtils.index(modules.getPath(), ((FridaLinuxSpecimen)specimen).getShortName())));

		// NB. this heuristic assumes all function bodies are contiguous in memory
		TargetSymbolNamespace symbols = m.find(TargetSymbolNamespace.class, binMod.getPath());
		// NB. ONCE is recommended resync mode for module symbols
		for (Entry<String, ? extends TargetObject> entry : waitOn(symbols.fetchElements())
				.entrySet()) {
			symbolsByKey.put(entry.getKey(), entry.getValue().as(TargetSymbol.class));
		}	
		
		return process;
}

	protected void runTestResume(DebuggerTestSpecimen specimen) throws Throwable {
		TargetProcess process = retryForProcessRunning(specimen, this);
		TargetResumable resumable = m.suitable(TargetResumable.class, process.getPath());
		AsyncState state =
			new AsyncState(m.suitable(TargetExecutionStateful.class, process.getPath()));
		TargetExecutionState st = waitOn(state.waitUntil(s -> s != TargetExecutionState.RUNNING));
		assertTrue(st.isAlive());
		waitOn(resumable.resume());
		retryVoid(() -> assertTrue(DebugModelConventions.isProcessAlive(process)),
			List.of(AssertionError.class));
	}
	
	protected void runTestKill(DebuggerTestSpecimen specimen) throws Throwable {
		TargetProcess process = retryForProcessRunning(specimen, this);
		TargetKillable killable = m.suitable(TargetKillable.class, process.getPath());
		waitOn(killable.kill());
	}
	
	protected void runTestLaunchThenResume(TargetLauncher launcher) throws Throwable {
		DebuggerTestSpecimen specimen = getPrintSpecimen();
		assertNull(getProcessRunning(specimen, this));
		runTestLaunch(specimen, launcher);
		runTestResumeTerminates(specimen);
	}

	@Test
	public void testLaunchResumeKill() throws Throwable {
		assumeTrue(m.hasKillableProcesses());
		m.build();

		TargetLauncher launcher = findLauncher();
		DebuggerTestSpecimen specimen = getPrintSpecimen();
		assertNull(getProcessRunning(specimen, this));
		runTestLaunch(specimen, launcher);
		runTestResume(specimen);
		runTestKill(specimen);
	}

	@Test
	public void testScan() throws Throwable {
		assumeTrue(m.hasKillableProcesses());
		m.build();

		TargetLauncher launcher = findLauncher();
		DebuggerTestSpecimen specimen = getPrintSpecimen();
		assertNull(getProcessRunning(specimen, this));
		TargetProcess process = runTestLaunch(specimen, launcher);
		
		FridaModelTargetProcess fproc = (FridaModelTargetProcess) process;
		ConsoleEventListener listener = new ConsoleEventListener("Found match at");
		fproc.getManager().addEventsListener(listener);

		FridaModelTargetMemoryContainerImpl memory = (FridaModelTargetMemoryContainerImpl) fproc.getCachedAttribute("Memory");
		FridaModelTargetMemoryScanImpl scan = (FridaModelTargetMemoryScanImpl) memory.getCachedAttribute("scan");
		Map<String, Object> map = new HashMap<>();
		Address address = symbolsByKey.get("overwrite").getValue();
		map.put("Address", address.toString());
		map.put("Size", 10L);
		map.put("Pattern", "48 65 6C 6C 6F");
		map.put("Stop", true);
		scan.invoke(map);
		
		waitForCondition(() -> {
			return listener.foundMatch();
		}, "Console output timed out");
		assertTrue(listener.getMatchingOutput().contains(address.toString()));
		runTestKill(specimen);
	}
	
	@Test
	public void testWatch() throws Throwable {
		assumeTrue(m.hasKillableProcesses());
		m.build();

		TargetLauncher launcher = findLauncher();
		DebuggerTestSpecimen specimen = getPrintSpecimen();
		assertNull(getProcessRunning(specimen, this));
		TargetProcess process = runTestLaunch(specimen, launcher);
		
		FridaModelTargetProcess fproc = (FridaModelTargetProcess) process;
		ConsoleEventListener listener = new ConsoleEventListener("read");
		fproc.getManager().addEventsListener(listener);

		FridaModelTargetMemoryContainerImpl memory = (FridaModelTargetMemoryContainerImpl) fproc.getCachedAttribute("Memory");
		FridaModelTargetMemoryWatchImpl watch = (FridaModelTargetMemoryWatchImpl) memory.getCachedAttribute("watch");
		Map<String, Object> map = new HashMap<>();
		Address address = symbolsByKey.get("overwrite").getValue();
		map.put("Address", address.toString());
		map.put("Size", 1L);
		ResourceFile installationDirectory = Application.getInstallationDirectory();
		map.put("OnAccess", installationDirectory + "/ghidra/Ghidra/Debug/Debugger-agent-frida/data/scripts/onAccess.js");
		watch.invoke(map);
		runTestResume(specimen);
		
		waitForCondition(() -> {
			return listener.foundMatch();
		}, "Console output timed out");
		assertTrue(listener.getMatchingOutput().contains(address.toString()));
		runTestKill(specimen);
	}
	
	@Test
	public void testInterceptor() throws Throwable {
		assumeTrue(m.hasKillableProcesses());
		m.build();

		TargetLauncher launcher = findLauncher();
		DebuggerTestSpecimen specimen = getStackSpecimen();
		assertNull(getProcessRunning(specimen, this));
		TargetProcess process = runTestLaunch(specimen, launcher);
		
		FridaModelTargetProcess fproc = (FridaModelTargetProcess) process;
		ConsoleEventListener listener = new ConsoleEventListener("entering");
		fproc.getManager().addEventsListener(listener);

		Map<String, Object> map = new HashMap<>();
		FridaModelTargetSymbol symbol = (FridaModelTargetSymbol) symbolsByKey.get("break_here");
		FridaModelTargetFunctionInterceptorImpl intercept = 
				(FridaModelTargetFunctionInterceptorImpl) symbol.getCachedAttribute("intercept");
		ResourceFile installationDirectory = Application.getInstallationDirectory();
		map.put("OnEnter", installationDirectory + "/ghidra/Ghidra/Debug/Debugger-agent-frida/data/scripts/onEnter.js");
		map.put("OnLeave", "");
		intercept.invoke(map);
		runTestResume(specimen);
		
		waitForCondition(() -> {
			return listener.foundMatch();
		}, "Console output timed out");
		runTestKill(specimen);
	}
	
	@Test
	public void testStalker() throws Throwable {
		assumeTrue(m.hasKillableProcesses());
		m.build();

		TargetLauncher launcher = findLauncher();
		DebuggerTestSpecimen specimen = getSpinSpecimen();
		assertNull(getProcessRunning(specimen, this));
		TargetProcess process = runTestLaunch(specimen, launcher);
		
		FridaModelTargetProcess fproc = (FridaModelTargetProcess) process;
		ConsoleEventListener listener = new ConsoleEventListener(":1");
		fproc.getManager().addEventsListener(listener);
		FridaModelTargetThreadContainerImpl threads = (FridaModelTargetThreadContainerImpl) fproc.getCachedAttribute("Threads");
		Map<String, TargetObject> elements = threads.getCachedElements();
		FridaModelTargetThreadImpl thread = (FridaModelTargetThreadImpl) elements.values().iterator().next();
		
		Map<String, Object> map = new HashMap<>();
		FridaModelTargetThreadStalkImpl stalk = 
				(FridaModelTargetThreadStalkImpl) thread.getCachedAttribute("stalk");
		ResourceFile installationDirectory = Application.getInstallationDirectory();
		map.put("OnCallSummary", installationDirectory + "/ghidra/Ghidra/Debug/Debugger-agent-frida/data/scripts/onCallSummary.js");
		map.put("EventCall", true);
		map.put("EventRet", false);
		map.put("EventExec", false);
		map.put("EventBlock", false);
		map.put("EventCompile", false);
		map.put("OnReceive", "");
		stalk.invoke(map);
		runTestResume(specimen);
		Thread.sleep(1000);		
		
		waitForCondition(() -> {
			return listener.foundMatch();
		}, "Console output timed out");
		runTestKill(specimen);
	}
	
	private class ConsoleEventListener implements FridaEventsListenerAdapter {
		
		private String match;
		private boolean foundMatch = false;
		private String matchingOutput; 
		
		public ConsoleEventListener(String match) {
			this.match = match;
		}

		@Override
		public void consoleOutput(String output, int mask) {
			if (output.contains(match)) {
				foundMatch = true;
				matchingOutput = output;
			}
		}
		
		public boolean foundMatch() {
			return foundMatch;
		}
		public String getMatchingOutput() {
			return matchingOutput;
		}
	}

}
