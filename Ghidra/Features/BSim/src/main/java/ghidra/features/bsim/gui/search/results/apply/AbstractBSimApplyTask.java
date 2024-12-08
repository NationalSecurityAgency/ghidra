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
package ghidra.features.bsim.gui.search.results.apply;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

import docking.DockingWindowManager;
import ghidra.app.services.ProgramManager;
import ghidra.features.bsim.gui.search.results.*;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramTask;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Generic task for applying information from a function match to the queried function
 */
public abstract class AbstractBSimApplyTask extends ProgramTask {

	private ServiceProvider serviceProvider;

	private List<BSimApplyResult> applyResults = new ArrayList<>();

	private List<BSimMatchResult> resultsToBeApplied;
	private FunctionManager functionManager;
	private ProgramManager programManager;
	private Set<Program> openedPrograms = new HashSet<>();

	private String taskName;

	public AbstractBSimApplyTask(Program program, String taskName, List<BSimMatchResult> results,
			ServiceProvider serviceProvider) {
		super(program, "Apply Function Names", true, true, true);
		this.taskName = taskName;
		this.serviceProvider = serviceProvider;
		functionManager = program.getFunctionManager();
		programManager = serviceProvider.getService(ProgramManager.class);
		this.resultsToBeApplied = results;
	}

	@Override
	public void doRun(TaskMonitor monitor) {
		if (programManager == null) {
			Msg.error(this, "Program Manager Service not found!");
			return;
		}
		try {
			applyResults(monitor);
			releaseOpenedPrograms();
		}
		catch (CancelledException e) {
			// user cancelled
		}

		Swing.runLater(() -> displayTaskResults(monitor.isCancelled()));
	}

	protected void releaseOpenedPrograms() {
		for (Program p : openedPrograms) {
			p.release(this);
		}
	}

	private void applyResults(TaskMonitor monitor) throws CancelledException {

		Map<Address, List<BSimMatchResult>> map = groupResultsBySearchAddress(monitor);

		monitor.initialize(map.size(), "Applying " + taskName + "...");

		for (Address address : map.keySet()) {
			applyResultsForAddress(address, map.get(address), monitor);
			monitor.increment();
		}
	}

	// groups results by the address of the function to be changed
	private Map<Address, List<BSimMatchResult>> groupResultsBySearchAddress(TaskMonitor monitor)
			throws CancelledException {
		monitor.initialize(resultsToBeApplied.size(), "Grouping results...");
		Map<Address, List<BSimMatchResult>> map = new HashMap<>();
		for (BSimMatchResult result : resultsToBeApplied) {
			monitor.increment();
			Address address = result.getAddress();
			List<BSimMatchResult> list = map.computeIfAbsent(address, k -> new ArrayList<>());
			list.add(result);
		}
		return map;
	}

	private void applyResultsForAddress(Address address, List<BSimMatchResult> resultsForAddress,
			TaskMonitor monitor) {

		Function targetFunction = functionManager.getFunctionAt(address);
		if (targetFunction == null) {
			error("Can't find original function", resultsForAddress.get(0));
			markRows(resultsForAddress, BSimResultStatus.ERROR);
			return;
		}

		List<Function> sourceFunctions = getSourceFunctions(resultsForAddress);
		if (sourceFunctions.isEmpty()) {
			markRows(resultsToBeApplied, BSimResultStatus.ERROR);
			return;
		}

		if (sourceFunctions.size() > 1) {
			if (!hasSameApplyData(sourceFunctions)) {
				applyResults.add(new BSimApplyResult(targetFunction.getName(),
					"<multiple functions>", BSimResultStatus.ERROR, targetFunction.getEntryPoint(),
					"Attempted to apply different " + taskName + "s to the same function"));
				markRows(resultsForAddress, BSimResultStatus.ERROR);
				return;
			}
		}

		BSimApplyResult applyResult = apply(targetFunction, sourceFunctions.get(0));
		applyResults.add(applyResult);
		markRows(resultsForAddress, applyResult.getStatus());
	}

	private List<Function> getSourceFunctions(List<BSimMatchResult> resultsForAddress) {
		List<Function> functions = new ArrayList<>();
		for (BSimMatchResult bSimMatchResult : resultsForAddress) {
			Function remoteFunction = getRemoteFunction(bSimMatchResult);
			if (remoteFunction != null) {
				functions.add(remoteFunction);
			}
		}
		return functions;
	}

	private Function getRemoteFunction(BSimMatchResult result) {
		Program remoteProgram = getRemoteProgram(result);
		if (remoteProgram == null) {
			return null;
		}

		FunctionDescription matchDescription = result.getMatchFunctionDescription();
		long addressOffset = matchDescription.getAddress();
		AddressSpace space = remoteProgram.getAddressFactory().getDefaultAddressSpace();
		Address address = space.getAddress(addressOffset);
		FunctionManager remoteFunctionManager = remoteProgram.getFunctionManager();
		Function matchFunction = remoteFunctionManager.getFunctionAt(address);

		if (matchFunction == null) {
			error("Couldn't find remote function at address " + address + " in remote program " +
				remoteProgram.getName(), result);
		}
		return matchFunction;
	}

	private Program getRemoteProgram(BSimMatchResult result) {
		URL url = getRemoteProgramURL(result);
		if (url == null) {
			return null;
		}

		Program remoteProgram = programManager.openCachedProgram(url, this);
		if (remoteProgram == null) {
			error("Open remote program failed: " + url, result);
			return null;
		}

		if (!openedPrograms.add(remoteProgram)) {
			// The program manager added 'this' as a consumer. We previously opened it and we don't
			// want the program to have the same consumer twice.
			remoteProgram.release(this);
		}
		return remoteProgram;
	}

	private void markRows(List<BSimMatchResult> list, BSimResultStatus state) {
		for (BSimMatchResult row : list) {
			row.setStatus(state);
		}
	}

	private URL getRemoteProgramURL(BSimMatchResult result) {
		String urlString = result.getExecutableURLString();
		try {
			return new URL(urlString);
		}
		catch (MalformedURLException e) {
			error("Bad URL: " + urlString, result);
		}
		return null;
	}

	private void displayTaskResults(boolean cancelled) {
		if (!hasErrorsOrIgnores()) {
			return;
		}

		BSimApplyResultsDisplayDialog resultsPanel =
			new BSimApplyResultsDisplayDialog(serviceProvider, applyResults, program);
		DockingWindowManager.showDialog(resultsPanel);
	}

	private boolean hasErrorsOrIgnores() {
		for (BSimApplyResult result : applyResults) {
			if (result.isError() || result.isIgnored()) {
				return true;
			}
		}
		return false;
	}

	private void error(String message, BSimMatchResult result) {
		applyResults.add(new BSimApplyResult(result, BSimResultStatus.ERROR, message));
	}

	protected abstract boolean hasSameApplyData(List<Function> functions);

	protected abstract BSimApplyResult apply(Function target, Function source);
}
