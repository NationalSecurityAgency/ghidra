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
package ghidra.app.plugin.core.analysis;

import java.util.*;

import generic.concurrent.*;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.ContextEvaluator;
import ghidra.program.util.SymbolicPropogator;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ConstantPropagationAnalyzer extends AbstractAnalyzer {

	private static final String NAME = " Constant Reference Analyzer";

	static final String DESCRIPTION =
		" Constant Propagation Analyzer for constant references computed with multiple instructions.";

	protected static final String OPTION_NAME = "Function parameter/return Pointer analysis";
	protected static final String OPTION_DESCRIPTION =
		"Turn on to check if values passed as parameters or returned could be pointer references";
	protected static final boolean OPTION_DEFAULT_VALUE = true;

	protected static final String POINTER_PARAM_OPTION_NAME = "Require pointer param data type";
	protected static final String POINTER_PARAM_OPTION_DESCRIPTION =
		"Turn on to require values passed as parameters or returned to be a known pointer data type";
	protected static final boolean POINTER_PARAM_OPTION_DEFAULT_VALUE = false;

	protected static final String STORED_OPTION_NAME = "Stored Value Pointer analysis";
	protected static final String STORED_OPTION_DESCRIPTION =
		"Turn on to check if values stored into memory or the stack could be pointer references";
	protected static final boolean STORED_OPTION_DEFAULT_VALUE = true;

	protected static final String TRUST_WRITEMEM_OPTION_NAME =
		"Trust values read from writable memory";
	protected static final String TRUST_WRITEMEM_OPTION_DESCRIPTION =
		"Turn on to trust values read from writable memory";
	protected static final boolean TRUST_WRITEMEM_OPTION_DEFAULT_VALUE = true;

	protected static final String MAX_THREAD_COUNT_OPTION_NAME = "Max Threads";
	protected static final String MAX_THREAD_COUNT_OPTION_DESCRIPTION =
		"Maximum threads for constant propagation.  Too many threads causes thrashing in DB.";
	protected static final int MAX_THREAD_COUNT_OPTION_DEFAULT_VALUE = 2;

	protected static final String MIN_KNOWN_REFADDRESS_OPTION_NAME = "Min absolute reference";
	protected static final String MIN_KNOWN_REFADDRESS_OPTION_DESCRIPTION =
		"Minimum address for calcuated constant store/load references";
	protected static final int MIN_KNOWN_REFADDRESS_OPTION_DEFAULT_VALUE = 4;

	protected static final String MIN_SPECULATIVE_REFADDRESS_OPTION_NAME =
		"Speculative reference min";
	protected static final String MIN_SPECULATIVE_REFADDRESS_OPTION_DESCRIPTION =
		"Minimum speculative reference address for offsets and parameters";
	protected static final int MIN_SPECULATIVE_REFADDRESS_OPTION_DEFAULT_VALUE = 1024;

	protected static final String MAX_SPECULATIVE_REFADDRESS_OPTION_NAME =
		"Speculative reference max";
	protected static final String MAX_SPECULATIVE_REFADDRESS_OPTION_DESCRIPTION =
		"Prototype - Maxmimum speculative reference address offset from the end of memory for offsets and parameters";
	protected static final int MAX_SPECULATIVE_REFADDRESS_OPTION_DEFAULT_VALUE = 256;
	
	protected static final String CREATE_COMPLEX_DATA_FROM_POINTERS_OPTION_NAME =
		"Create Data from pointer";
	protected static final String CREATE_COMPLEX_DATA_FROM_POINTERS_OPTION_DESCRIPTION =
		"Create complex data types from pointers if the data type is known, currently from function parameters.";
	protected static final boolean CREATE_COMPLEX_DATA_FROM_POINTERS_OPTION_DEFAULT_VALUE = false;

	protected final static int NOTIFICATION_INTERVAL = 100;

	protected boolean checkParamRefsOption = OPTION_DEFAULT_VALUE;
	protected boolean checkPointerParamRefsOption = POINTER_PARAM_OPTION_DEFAULT_VALUE;
	protected boolean checkStoredRefsOption = STORED_OPTION_DEFAULT_VALUE;
	protected boolean trustWriteMemOption = TRUST_WRITEMEM_OPTION_DEFAULT_VALUE;
	protected boolean createComplexDataFromPointers = CREATE_COMPLEX_DATA_FROM_POINTERS_OPTION_DEFAULT_VALUE;
	
	protected int maxThreadCount = MAX_THREAD_COUNT_OPTION_DEFAULT_VALUE;
	protected long minStoreLoadRefAddress = MIN_KNOWN_REFADDRESS_OPTION_DEFAULT_VALUE;
	protected long minSpeculativeRefAddress = MIN_SPECULATIVE_REFADDRESS_OPTION_DEFAULT_VALUE;
	protected long maxSpeculativeRefAddress = MAX_SPECULATIVE_REFADDRESS_OPTION_DEFAULT_VALUE;

	protected boolean followConditional = false;

	final static HashSet<String> handledProcessors = new HashSet<String>();
	protected String processorName = "Basic";
	protected AddressSetView EMPTY_ADDRESS_SET = new AddressSet();

	public ConstantPropagationAnalyzer() {
		this("Basic");
	}

	public ConstantPropagationAnalyzer(String processorName) {
		super(processorName + NAME, processorName + DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		claimProcessor(processorName);
		this.processorName = processorName;
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.before().before().before().before());
	}

	public ConstantPropagationAnalyzer(String processorName, AnalyzerType type) {
		super(processorName + NAME, processorName + DESCRIPTION, type);
	}

	/**
	 * Called to to register a more specific analyzer.
	 *
	 * @param processorName
	 */
	static public void claimProcessor(String processorName) {
		handledProcessors.add(processorName);
	}

	/**
	 * Called to register a more specific analyzer.
	 *
	 * @param processorName
	 */
	static public boolean isClaimedProcessor(String processorName) {
		return handledProcessors.contains(processorName);
	}

	@Override
	public boolean canAnalyze(Program program) {
		// Set the default for checking parameter passing
		// don't look for constant passing in things that have a small address space, or is segmented
		// unless there is a good data type at the location
		boolean isHarvard = program.getLanguage().getDefaultSpace() != program.getLanguage().getDefaultDataSpace();
		checkPointerParamRefsOption = program.getDefaultPointerSize() <= 2 || isHarvard;
		
		checkParamRefsOption = !(program.getAddressFactory()
				.getDefaultAddressSpace() instanceof SegmentedAddressSpace);

		if (processorName.equals("Basic")) {
			if (handledProcessors.contains(program.getLanguage().getProcessor().toString())) {
				return false;
			}

			return true;
		}
		return program.getLanguage()
				.getProcessor()
				.equals(Processor.findOrPossiblyCreateProcessor(processorName));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		AddressSet unanalyzedSet = new AddressSet(set);

		removeUninitializedBlocks(program, unanalyzedSet);

		try {
			// first split out all the function locations, make those the starts
			// remove those from the bodies from the given set of addresses
			Set<Address> locations = new HashSet<Address>();
			findLocationsRemoveFunctionBodies(program, unanalyzedSet, locations, monitor);

			int locationCount = locations.size();
			monitor.initialize(locationCount);
			if (locationCount != 0) {
				AddressSetView resultSet = runAddressAnalysis(program, locations, monitor);
				// get rid of any reached addresses
				unanalyzedSet.delete(resultSet);
			}

			// now slog through the rest single threaded
			if (!unanalyzedSet.isEmpty()) {
				analyzeSet(program, unanalyzedSet, monitor);
			}
		}
		catch (CancelledException ce) {
			throw ce;
		}
		catch (Exception e) {
			Msg.error(this, "caught exception", e);
			e.printStackTrace();
		}

		return true;
	}

	/**
	 * Get rid of uninitialized memory blocks from set to analyze.
	 * Uninitialized memory can't have instructions with no bytes.
	 * 
	 * @param program program
	 * @param set remove blocks without bytes
	 */
	protected void removeUninitializedBlocks(Program program, AddressSet set) {
		MemoryBlock[] blocks = program.getMemory().getBlocks();
		for (MemoryBlock block : blocks) {
			if (block.isInitialized()) {
				continue;
			}
			// ByteMapped blocks currently are uninitialized.
			// Not optimal, because there might not be initialized
			// bytes in the whole block, but the savings of checking
			// would be negligible
			if (block.isMapped()) {
				continue;
			}

			set.deleteRange(block.getStart(), block.getEnd());
		}
	}

	/**
	 * Find function locations and leave only the function entry point in the address
	 * set.  Anything not in a function is still in the address set.
	 * 
	 * @param program program
	 * @param set remove known function bodies from the set, leave entry points
	 * @param locations set of known function start addresses
	 * @param monitor to cancel
	 * @throws CancelledException if cancelled
	 */
	protected void findLocationsRemoveFunctionBodies(Program program, AddressSet set,
			Set<Address> locations, TaskMonitor monitor) throws CancelledException {

		monitor.setMessage("Finding function locations...");
		long total = set.getNumAddresses();
		monitor.initialize(total);

		// iterate over functions in program
		// add each defined function start to the list
		// return the address set that is minus the bodies of each function
		AddressSet inBodySet = new AddressSet();
		Iterator<Function> fiter = program.getFunctionManager().getFunctionsOverlapping(set);
		while (fiter.hasNext()) {
			monitor.checkCancelled();
			Function function = fiter.next();
			locations.add(function.getEntryPoint());
			inBodySet.add(function.getBody());
		}

		monitor.setProgress(total - inBodySet.getNumAddresses());
		set.delete(inBodySet);

		// set now has Stuff in it that isn't in a recorded function body
		ReferenceManager referenceManager = program.getReferenceManager();
		AddressIterator referenceDestinationIterator =
			referenceManager.getReferenceDestinationIterator(set, true);

		AddressSet outOfBodySet = new AddressSet();
		while (referenceDestinationIterator.hasNext()) {
			monitor.checkCancelled();
			Address address = referenceDestinationIterator.next();
			ReferenceIterator referencesTo = referenceManager.getReferencesTo(address);
			while (referencesTo.hasNext()) {
				Reference reference = referencesTo.next();
				if (reference.getReferenceType().isCall()) {
					locations.add(address);
					outOfBodySet.add(address);
					// could subtract all local non-call flows from the set, but
					// might be extra work...
					break;
				}
			}
		}

		monitor.incrementProgress(outOfBodySet.getNumAddresses());
		set.delete(outOfBodySet);

		// now iterate over individual address ranges, and use first address as a start
		outOfBodySet = new AddressSet();
		AddressRangeIterator addressRanges = set.getAddressRanges();
		while (addressRanges.hasNext()) {
			monitor.checkCancelled();
			AddressRange addressRange = addressRanges.next();
			locations.add(addressRange.getMinAddress());
			outOfBodySet.add(addressRange.getMinAddress());
		}

		monitor.incrementProgress(outOfBodySet.getNumAddresses());
		set.delete(outOfBodySet);
	}

	/**
	 * Run constant propagation starting at address in locations
	 * 
	 * @param program program
	 * @param locations function entry points
	 * @param monitor to cancel
	 * @return set of addresses covered during constant analysis
	 * 
	 * @throws CancelledException
	 * @throws InterruptedException
	 * @throws Exception
	 */
	protected AddressSetView runAddressAnalysis(final Program program, final Set<Address> locations,
			final TaskMonitor monitor) throws CancelledException, InterruptedException, Exception {

		monitor.checkCancelled();

		final AddressSet analyzedSet = new AddressSet();
		if (locations.isEmpty()) {
			return analyzedSet;
		}

		GThreadPool pool = AutoAnalysisManager.getSharedAnalsysThreadPool();
		monitor.setMessage("Analyzing functions...");
		monitor.setMaximum(locations.size());

		QCallback<Address, AddressSetView> callback = new QCallback<Address, AddressSetView>() {
			@Override
			public AddressSetView process(Address loc, TaskMonitor taskMonitor) {
				synchronized (analyzedSet) {
					if (analyzedSet.contains(loc)) {
						taskMonitor.incrementProgress(1);
						return EMPTY_ADDRESS_SET;
					}
				}

				try {
					AddressSetView result = analyzeLocation(program, loc, null, taskMonitor);
					synchronized (analyzedSet) {
						analyzedSet.add(result);
					}

					taskMonitor.incrementProgress(1);
					return result;
				}
				catch (CancelledException e) {
					return null; // monitor was cancelled
				}
			}
		};

		// bound check thread limit
		if (maxThreadCount > pool.getMaxThreadCount() || maxThreadCount < 1) {
			maxThreadCount = 1;
		}

		// @formatter:off
		ConcurrentQ<Address, AddressSetView> queue = new ConcurrentQBuilder<Address, AddressSetView>()
			.setThreadPool(pool)
			.setMaxInProgress(maxThreadCount)
			.setMonitor(monitor)
			.build(callback);
		// @formatter:on

		queue.add(locations);

		queue.waitUntilDone();

		return analyzedSet;
	}

	/**
	 * Analyze all addresses in todoSet
	 * 
	 * @param program program
	 * @param todoSet addresses that are not in functions
	 * @param monitor to cancel
	 * 
	 * @throws CancelledException
	 */
	public void analyzeSet(Program program, AddressSet todoSet, TaskMonitor monitor)
			throws CancelledException {

		long totalNumAddresses = todoSet.getNumAddresses();
		monitor.initialize(totalNumAddresses);

		// Iterate over all new instructions
		// Evaluate each operand
		Listing listing = program.getListing();
		int count = 0;
		while (!todoSet.isEmpty()) {
			monitor.checkCancelled();

			if ((count++ % NOTIFICATION_INTERVAL) == 0) {
				monitor.setProgress(totalNumAddresses - todoSet.getNumAddresses());
			}

			// find the next instruction starting at the minimum addr in the set
			Address nextAddr = todoSet.getMinAddress();
			Instruction instr = listing.getInstructionAt(nextAddr);
			if (instr == null) {
				// no instr at min address, find the next after
				instr = listing.getInstructionAfter(nextAddr);
				if (instr == null) {
					break; // no more to do
				}

				// the instruction after could land outside the set,
				// but that will only happen once, then the
				// search will start again inside the set
				nextAddr = instr.getMinAddress();
				if (!todoSet.contains(nextAddr)) {
					todoSet.deleteFromMin(nextAddr);
					continue;
				}
			}

			Address start = instr.getMinAddress();
			AddressSetView resultSet = analyzeLocation(program, start, todoSet, monitor);
			if (resultSet != null) { // null sometimes when cancelled
				// if the first instruction found in todoSet, was past the beginning of
				// the todoSet, there will be no instructions before start
				if (!start.equals(todoSet.getMinAddress())) {
					// delete all addresses up to the start from the todo set
					todoSet.deleteFromMin(start);
				}
				// now get rid of all the instructions that were analyzed
				todoSet.delete(resultSet);
			}
		}
	}

	/**
	 * Analyze a single location
	 * 
	 * @param program - program to analyze
	 * @param start - location to start flowing constants
	 * @param set - restriction set of addresses to analyze
	 * @param monitor - monitor to check canceled
	 * 
	 * @return - set of addresses actually flowed to
	 * @throws CancelledException
	 */
	public AddressSetView analyzeLocation(final Program program, Address start, AddressSetView set,
			final TaskMonitor monitor) throws CancelledException {

		monitor.checkCancelled();

		// get the function body
		if (program.getListing().getInstructionAt(start) == null) {
			return new AddressSet();
		}

		Address flowStart = start;
		AddressSetView flowSet = set;
		final Function func = program.getFunctionManager().getFunctionContaining(start);
		if (func != null) {
			AddressSetView body = func.getBody();
			// don't override flow set if only one address
			if (body.getNumAddresses() > 1) {
				flowSet = body;
			}
			flowStart = func.getEntryPoint();
		}

		SymbolicPropogator symEval = new SymbolicPropogator(program);
		symEval.setParamRefCheck(checkParamRefsOption);

		symEval.setParamPointerRefCheck(checkPointerParamRefsOption);

		symEval.setReturnRefCheck(checkParamRefsOption);
		symEval.setStoredRefCheck(checkStoredRefsOption);

		// follow all flows building up context
		// use context to fill out addresses on certain instructions 
		return flowConstants(program, flowStart, flowSet, symEval, monitor);
	}

	/**
	 * Actually use the setup evauluator to flow the constants
	 * 
	 * @param flowStart - address to start flowing at
	 * @param flowSet - address set to restrict constant flowing to
	 * @param symEval - symbolic propagator to be used
	 * @param monitor - monitor to check canceled
	 * @return the address set of instructions which were followed
	 * @throws CancelledException
	 */
	public AddressSetView flowConstants(final Program program, Address flowStart,
			AddressSetView flowSet, final SymbolicPropogator symEval, final TaskMonitor monitor)
			throws CancelledException {

		ContextEvaluator eval = new ConstantPropagationContextEvaluator(monitor)
				.setTrustWritableMemory(trustWriteMemOption)
			    .setMinpeculativeOffset(minSpeculativeRefAddress)
			    .setMaxSpeculativeOffset(maxSpeculativeRefAddress)
			    .setMinStoreLoadOffset(minStoreLoadRefAddress)
			    .setCreateComplexDataFromPointers(createComplexDataFromPointers);

		return symEval.flowConstants(flowStart, flowSet, eval, true, monitor);
	}

	public final void markDataAsConstant(Data data) {
		SettingsDefinition[] settings = data.getDataType().getSettingsDefinitions();
		for (SettingsDefinition setting : settings) {
			if (setting instanceof MutabilitySettingsDefinition) {
				MutabilitySettingsDefinition mutabilitySetting =
					(MutabilitySettingsDefinition) setting;
				mutabilitySetting.setChoice(data, MutabilitySettingsDefinition.CONSTANT);
			}
		}
	}

	public final void createData(Program program, Address address, int size) {
		if (size < 1 || size > 8) {
			return;
		}

		if (!program.getListing().isUndefined(address, address)) {
			Data data = program.getListing().getDataAt(address);
			if (data == null) {
				return;
			}
			if (data.getDataType() instanceof Undefined) {
				if (data.getLength() >= size) {
					return;
				}
				program.getListing().clearCodeUnits(address, address, false);
			}
			else {
				return;
			}
		}

		DataType dt = Undefined.getUndefinedDataType(size);
		try {
			program.getListing().createData(address, dt);
		}
		catch (CodeUnitInsertionException e) {
			// don't care; we tried
		}
	}

	@Override
	public boolean getDefaultEnablement(Program p) {
		// always enabled, will be disabled if another analyzer has claimed/registered for a real processor
		// in the canAnalyze() function.
		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME, checkParamRefsOption, null, OPTION_DESCRIPTION);
		options.registerOption(STORED_OPTION_NAME, checkStoredRefsOption, null,
			STORED_OPTION_DESCRIPTION);
		options.registerOption(TRUST_WRITEMEM_OPTION_NAME, trustWriteMemOption, null,
			TRUST_WRITEMEM_OPTION_DESCRIPTION);

		options.registerOption(CREATE_COMPLEX_DATA_FROM_POINTERS_OPTION_NAME, createComplexDataFromPointers, null,
			CREATE_COMPLEX_DATA_FROM_POINTERS_OPTION_DESCRIPTION);
		
		options.registerOption(POINTER_PARAM_OPTION_NAME, checkPointerParamRefsOption, null,
			POINTER_PARAM_OPTION_DESCRIPTION);

		options.registerOption(MAX_THREAD_COUNT_OPTION_NAME, maxThreadCount, null,
			MAX_THREAD_COUNT_OPTION_DESCRIPTION);

		options.registerOption(MIN_KNOWN_REFADDRESS_OPTION_NAME, minStoreLoadRefAddress, null,
			MIN_KNOWN_REFADDRESS_OPTION_DESCRIPTION);

		long size = program.getAddressFactory().getDefaultAddressSpace().getSize();
		minSpeculativeRefAddress = size * 16;
		options.registerOption(MIN_SPECULATIVE_REFADDRESS_OPTION_NAME, minSpeculativeRefAddress, null,
			MIN_SPECULATIVE_REFADDRESS_OPTION_DESCRIPTION);

		maxSpeculativeRefAddress = size * 8;
		options.registerOption(MAX_SPECULATIVE_REFADDRESS_OPTION_NAME, maxSpeculativeRefAddress, null,
			MAX_SPECULATIVE_REFADDRESS_OPTION_DESCRIPTION);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		checkParamRefsOption = options.getBoolean(OPTION_NAME, checkParamRefsOption);

		checkPointerParamRefsOption =
			options.getBoolean(POINTER_PARAM_OPTION_NAME, checkPointerParamRefsOption);

		checkStoredRefsOption = options.getBoolean(STORED_OPTION_NAME, checkStoredRefsOption);
		trustWriteMemOption = options.getBoolean(TRUST_WRITEMEM_OPTION_NAME, trustWriteMemOption);
		
		createComplexDataFromPointers = options.getBoolean(CREATE_COMPLEX_DATA_FROM_POINTERS_OPTION_NAME, createComplexDataFromPointers);

		maxThreadCount = options.getInt(MAX_THREAD_COUNT_OPTION_NAME, maxThreadCount);

		// TODO: there should be a getAddress on option that validates and allows entry of addresses
		minStoreLoadRefAddress =
			options.getLong(MIN_KNOWN_REFADDRESS_OPTION_NAME, minStoreLoadRefAddress);
		minSpeculativeRefAddress =
			options.getLong(MIN_SPECULATIVE_REFADDRESS_OPTION_NAME, minSpeculativeRefAddress);
		maxSpeculativeRefAddress =
			options.getLong(MAX_SPECULATIVE_REFADDRESS_OPTION_NAME, maxSpeculativeRefAddress);
	}

}
