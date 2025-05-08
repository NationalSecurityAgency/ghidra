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
package ghidra.app.plugin.core.function;

import java.util.*;

import ghidra.app.cmd.function.FunctionStackAnalysisCmd;
import ghidra.app.cmd.function.NewFunctionStackAnalysisCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class StackVariableAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Stack";
	private static final String DESCRIPTION = "Creates stack variables for a function.";
	
	protected static final String MAX_THREAD_COUNT_OPTION_NAME = "Max Threads";
	protected static final String MAX_THREAD_COUNT_OPTION_DESCRIPTION =
		"Maximum threads for stack variable reference creation.  Too many threads causes thrashing in DB.";
	protected static final int MAX_THREAD_COUNT_OPTION_DEFAULT_VALUE = 2;
	
	protected int maxThreadCount = MAX_THREAD_COUNT_OPTION_DEFAULT_VALUE;
	private boolean doNewStackAnalysis = true;
	private boolean doCreateLocalStackVars = true;
	private boolean doCreateStackParams = false;

	public StackVariableAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after().after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
		BackgroundCommand<Program> cmd;

		// first split out all the function locations, make those the starts
		// remove those from the bodies from the given set of addresses
		Set<Address> locations = new HashSet<Address>();
		findDefinedFunctions(program, set, locations, monitor);

		int locationCount = locations.size();
		monitor.initialize(locationCount);
		try {
			monitor.setMessage(getName());
			AddressSetView resultSet = runParallelAddressAnalysis(program, locations, null, maxThreadCount, monitor);
		}
		catch (Exception e) {
			Msg.error(this, "caught exception", e);
			e.printStackTrace();
		}

		return true;
	}
	
	@Override
	public AddressSetView analyzeLocation(final Program program, Address start, AddressSetView set,
			final TaskMonitor monitor) throws CancelledException {
		BackgroundCommand<Program> cmd;
		
		if (doNewStackAnalysis) {
			cmd = new NewFunctionStackAnalysisCmd(new AddressSet(start, start), doCreateStackParams, doCreateLocalStackVars,
				false);
		}
		else {
			cmd = new FunctionStackAnalysisCmd(new AddressSet(start, start), doCreateStackParams, doCreateLocalStackVars,
				false);
		}	
		cmd.applyTo(program, monitor);
		
		return EMPTY_ADDRESS_SET;
	}
	
	/**
	 * Find function locations and adding the function entry points to locations
	 * 
	 * @param program program
	 * @param set remove known function bodies from the set, leave entry points
	 * @param locations set of known function start addresses
	 * @param monitor to cancel
	 * @throws CancelledException if cancelled
	 */
	protected void findDefinedFunctions(Program program, AddressSetView set,
			Set<Address> locations, TaskMonitor monitor) throws CancelledException {

		monitor.setMessage("Finding function locations...");
		long total = set.getNumAddresses();
		monitor.initialize(total);

		// iterate over functions in program
		// add each defined function start to the list
		// return the address set that is minus the bodies of each function
		Iterator<Function> fiter = program.getFunctionManager().getFunctionsOverlapping(set);
		while (fiter.hasNext()) {
			monitor.checkCancelled();
			Function function = fiter.next();
			locations.add(function.getEntryPoint());
		}
	}

//	private boolean useOldStackAnalysisByDefault(Program program) {
//		Language language = program.getLanguage();
//		if (language.getProcessor().equals(Processor.findOrPossiblyCreateProcessor("x86"))) {
//			if (language.getLanguageDescription().getSize() == 16) {
//				// Prefer using old stack analysis for x86 16-bit with segmented addresses
//				return true;
//			}
//		}
//		return false;
//	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(GhidraLanguagePropertyKeys.USE_NEW_FUNCTION_STACK_ANALYSIS,
			true, null,
			"Use General Stack Reference Propogator (This works best on most processors)");

		options.registerOption("Create Local Variables", doCreateLocalStackVars, null,
			"Create Function Local stack variables and references");

		options.registerOption("Create Param Variables", doCreateStackParams, null,
			"Create Function Parameter stack variables and references");
		
		options.registerOption(MAX_THREAD_COUNT_OPTION_NAME, maxThreadCount, null,
			MAX_THREAD_COUNT_OPTION_DESCRIPTION);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		doNewStackAnalysis =
			options.getBoolean(GhidraLanguagePropertyKeys.USE_NEW_FUNCTION_STACK_ANALYSIS,
				true);

		doCreateLocalStackVars =
			options.getBoolean("Create Local Variables", doCreateLocalStackVars);

		doCreateStackParams = options.getBoolean("Create Param Variables", doCreateStackParams);
		
		maxThreadCount = options.getInt(MAX_THREAD_COUNT_OPTION_NAME, maxThreadCount);
	}

}
