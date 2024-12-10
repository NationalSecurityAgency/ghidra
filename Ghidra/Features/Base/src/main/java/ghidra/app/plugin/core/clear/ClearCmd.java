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
package ghidra.app.plugin.core.clear;

import static ghidra.app.plugin.core.clear.ClearOptions.ClearType.*;

import java.util.Iterator;
import java.util.Set;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ClearCmd extends BackgroundCommand<Program> {
	private static final int EVENT_LIMIT = 1000;

	private AddressSetView view;
	private ClearOptions options;
	private boolean sendIndividualEvents = false;

	private TaskMonitor monitor;
	private Program program;

	/**
	 * A convenience constructor to clear a single code unit.
	 *
	 * @param cu the code unit to clear
	 * @param options the options used while clearing
	 */
	public ClearCmd(CodeUnit cu, ClearOptions options) {
		this(new AddressSet(new AddressRangeImpl(cu.getMinAddress(), cu.getMaxAddress())), options,
			true);
	}

	/**
	 * Clears using the given address set and options.
	 *
	 * @param view the addresses over which to clear
	 * @param options the options used while clearing
	 */
	public ClearCmd(AddressSetView view, ClearOptions options) {
		this(view, options, view.getNumAddresses() < EVENT_LIMIT);
	}

	/**
	 * Clears over the given range, <b>clearing only code</b>.  To clear other items,
	 * use {@link #ClearCmd(AddressSetView,ClearOptions)}.
	 *
	 * @param view the addresses over which to clear
	 */
	public ClearCmd(AddressSetView view) {
		this(view, null, view.getNumAddresses() < EVENT_LIMIT);
	}

	protected ClearCmd(AddressSetView view, ClearOptions options, boolean sendIndividualEvents) {
		super(options != null ? "Clear with Options" : "Clear code", true, true, true);
		this.view = view;
		this.options = options;
		this.sendIndividualEvents = sendIndividualEvents;

		if (this.options == null) {
			this.options = new ClearOptions(false);
			this.options.setShouldClear(INSTRUCTIONS, true);
			this.options.setShouldClear(DATA, true);
		}
	}

	@Override
	public boolean applyTo(Program p, TaskMonitor taskMonitor) {
		this.monitor = taskMonitor;
		this.program = p;
		boolean wasEabled = program.isSendingEvents();
		try {
			program.setEventsEnabled(sendIndividualEvents);
			return doApplyTo();
		}
		finally {
			program.setEventsEnabled(wasEabled);
			program = null;
			monitor = null;
		}
	}

	private boolean doApplyTo() {

		try {
			doApplyWithCancel();
			monitor.setMessage("Clear completed");
			return true;
		}
		catch (CancelledException e) {
			return true;
		}
	}

	private boolean doApplyWithCancel()
			throws CancelledException {

		if (monitor == null) {
			monitor = TaskMonitor.DUMMY;
		}

		if (options.shouldClear(EQUATES)) {
			clearEquates(view);
		}
		if (options.shouldClear(INSTRUCTIONS) || options.shouldClear(DATA)) {
			clearInstructionsAndOrData(view);
		}
		if (options.shouldClear(COMMENTS)) {
			clearComments(view);
		}
		if (options.shouldClear(FUNCTIONS)) {
			clearFunctions(view);
		}
		if (options.shouldClear(SYMBOLS)) {
			clearSymbols(view);
		}
		if (options.shouldClear(PROPERTIES)) {
			clearProperties(view);
		}
		if (options.shouldClear(REGISTERS)) {
			clearRegisters(view);
		}
		if (options.shouldClear(BOOKMARKS)) {
			clearBookmarks(view);
		}

		// if clearing instructions and data, no need to handle references separately
		if (options.shouldClear(INSTRUCTIONS) && options.shouldClear(DATA)) {
			return true;
		}

		Set<SourceType> referenceSourceTypesToClear = options.getReferenceSourceTypesToClear();
		if (!referenceSourceTypesToClear.isEmpty()) {
			clearReferences(view, referenceSourceTypesToClear);
		}
		return true;
	}

	private void clearSymbols(AddressSetView clearView)
			throws CancelledException {

		if (clearView.isEmpty()) {
			return;
		}

		monitor.initialize(clearView.getNumAddresses());
		monitor.setMessage("Clearing symbols...");

		SymbolTable symbolTable = program.getSymbolTable();

		// Use ranges to keep track of progress
		int numDone = 0;
		int previousRangeAddrCnt = 0;
		for (AddressRange range : clearView.getAddressRanges()) {
			Address rangeMin = range.getMinAddress();
			SymbolIterator symbolIter = symbolTable.getSymbolIterator(rangeMin, true);
			while (symbolIter.hasNext()) {
				monitor.checkCancelled();
				Symbol s = symbolIter.next();
				if (s.getAddress().compareTo(range.getMaxAddress()) > 0) {
					break; // done with range
				}
				if (s.getSymbolType() != SymbolType.LABEL) {
					continue;
				}
				if (s.isPinned()) {
					continue;
				}

				s.delete();
				numDone++;

				if ((numDone % 10000) == 0) {
					int progress = previousRangeAddrCnt + (int) (s.getAddress().subtract(rangeMin));
					monitor.setProgress(progress);

					// Allow Swing a chance to paint components that may require a DB lock
					Swing.allowSwingToProcessEvents();
				}
			}
			previousRangeAddrCnt += range.getLength();
		}
	}

	private void clearComments(AddressSetView clearView)
			throws CancelledException {

		monitor.initialize(clearView.getNumAddresses());
		monitor.setMessage("Starting to clear comments...");

		Listing listing = program.getListing();
		AddressRangeIterator iter = clearView.getAddressRanges();
		int progress = 0;
		while (iter.hasNext()) {

			monitor.checkCancelled();
			AddressRange range = iter.next();
			listing.clearComments(range.getMinAddress(), range.getMaxAddress());
			progress += range.getLength();
			monitor.setProgress(progress);
		}
	}

	private void clearProperties(AddressSetView clearView)
			throws CancelledException {

		monitor.initialize(clearView.getNumAddresses());
		monitor.setMessage("Starting to clear properties...");

		Listing listing = program.getListing();
		AddressRangeIterator iter = clearView.getAddressRanges();
		int progress = 0;
		while (iter.hasNext()) {
			AddressRange range = iter.next();
			listing.clearProperties(range.getMinAddress(), range.getMaxAddress(), monitor);
			progress += range.getLength();
			monitor.setProgress(progress);
		}
	}

	private void clearFunctions(AddressSetView clearView)
			throws CancelledException {

		FunctionManager manager = program.getFunctionManager();
		int count = manager.getFunctionCount();

		monitor.setMessage("Clearing functions...");
		monitor.initialize(count);

		FunctionIterator iter = manager.getFunctions(clearView, true);
		while (iter.hasNext()) {

			monitor.checkCancelled();
			Function func = iter.next();
			monitor.incrementProgress(1);
			manager.removeFunction(func.getEntryPoint());
		}
	}

	private void clearRegisters(AddressSetView clearView)
			throws CancelledException {

		monitor.initialize(clearView.getNumAddresses());
		monitor.setMessage("Starting to clear registers...");
		ProgramContext pc = program.getProgramContext();
		AddressRangeIterator iter = clearView.getAddressRanges();
		while (iter.hasNext()) {
			AddressRange range = iter.next();
			removeRegisters(pc, range);
		}
	}

	private void clearEquates(AddressSetView clearView)
			throws CancelledException {
		monitor.initialize(100);
		monitor.setMessage("Starting to clear equates...");

		EquateTable eqtbl = program.getEquateTable();
		Iterator<Equate> iter = eqtbl.getEquates();
		while (iter.hasNext()) {

			monitor.checkCancelled();
			Equate eq = iter.next();
			EquateReference[] refs = eq.getReferences();

			for (EquateReference ref : refs) {
				if (clearView.contains(ref.getAddress())) {
					eq.removeReference(ref.getAddress(), ref.getOpIndex());
				}
			}
			if (eq.getReferences().length == 0) {
				eqtbl.removeEquate(eq.getName());
			}
			monitor.incrementProgress(1);
		}
	}

	private void clearInstructionsAndOrData(AddressSetView clearView)
			throws CancelledException {

		boolean clearInstructions = options.shouldClear(INSTRUCTIONS);
		boolean clearData = options.shouldClear(DATA);

		monitor.initialize(clearView.getNumAddresses());
		monitor.setMessage(getMessage(clearInstructions, clearData));

		for (AddressRange range : clearView.getAddressRanges()) {
			clearCode(range, clearInstructions, clearData);
		}
	}

	private void clearCode(AddressRange range, boolean clearInstructions, boolean clearData)
			throws CancelledException {

		if (clearData && clearInstructions) {
			clearCodeUnits(range);
			return;
		}

		AddressSet set = clearInstructions ? getInstructionRanges(range) : getDataRanges(range);

		for (AddressRange r : set.getAddressRanges()) {
			clearCodeUnits(r);
		}

		// also increment monitor for skipped address
		monitor.incrementProgress(range.getLength() - set.getNumAddresses());
	}

	private AddressSet getInstructionRanges(AddressRange range) {
		AddressSet addresses = new AddressSet();
		Listing listing = program.getListing();
		Address end = range.getMaxAddress();

		for (Instruction inst : listing.getInstructions(range.getMinAddress(), true)) {
			if (inst.getMinAddress().compareTo(end) > 0) {
				break;
			}
			addresses.add(inst.getMinAddress(), inst.getMaxAddress());
		}
		return addresses;
	}

	private AddressSet getDataRanges(AddressRange range) {
		AddressSet addresses = new AddressSet();
		Listing listing = program.getListing();
		Address end = range.getMaxAddress();

		for (Data data : listing.getDefinedData(range.getMinAddress(), true)) {
			if (data.getMinAddress().compareTo(end) > 0) {
				break;
			}
			addresses.add(data.getMinAddress(), data.getMaxAddress());
		}
		return addresses;
	}

	private void clearCodeUnits(AddressRange range) throws CancelledException {

		Listing listing = program.getListing();

		boolean clearContext = options.shouldClear(REGISTERS);
		AddressRangeChunker chunker = new AddressRangeChunker(range, 10000);
		for (AddressRange chunk : chunker) {

			Address min = chunk.getMinAddress();
			Address max = chunk.getMaxAddress();

			monitor.setMessage("Clearing code at " + min);

			listing.clearCodeUnits(min, max, clearContext, monitor);

			int numDone = (int) (max.subtract(min) + 1);
			monitor.incrementProgress(numDone);

			// Allow the Swing thread a chance to paint components that may require a DB lock
			Swing.allowSwingToProcessEvents();
		}
	}

	private void clearReferences(AddressSetView clearView, Set<SourceType> sourceTypesToClear)
			throws CancelledException {

		if (clearView.isEmpty()) {
			return;
		}

		monitor.initialize(clearView.getNumAddresses());
		monitor.setMessage("Clearing references...");

		ReferenceManager referenceManager = program.getReferenceManager();
		AddressIterator it = referenceManager.getReferenceSourceIterator(clearView, true);
		removeRefs(it, sourceTypesToClear);
	}

	private void clearBookmarks(AddressSetView clearView) throws CancelledException {

		if (clearView.isEmpty()) {
			return;
		}
		monitor.initialize(clearView.getNumAddresses());
		monitor.setMessage("Clearing bookmarks...");

		BookmarkManager bookmarkMgr = program.getBookmarkManager();
		bookmarkMgr.removeBookmarks(clearView, monitor);
	}

	private void removeRegisters(ProgramContext pc, AddressRange range)
			throws CancelledException {
		for (Register reg : pc.getRegistersWithValues()) {
			monitor.checkCancelled();

			if (reg.isProcessorContext()) {
				continue; // skip context register
			}
			try {
				pc.remove(range.getMinAddress(), range.getMaxAddress(), reg);
			}
			catch (ContextChangeException e) {
				Msg.error(this, e.getMessage() + " in range " + range, e); // unexpected
			}
		}
	}

	private void removeRefs(AddressIterator iter, Set<SourceType> sourceTypesToClear)
			throws CancelledException {

		ReferenceManager referenceManager = program.getReferenceManager();
		while (iter.hasNext()) {

			monitor.checkCancelled();

			Address addr = iter.next();
			Reference[] refs = referenceManager.getReferencesFrom(addr);
			for (Reference ref : refs) {
				if (monitor.isCancelled()) {
					break;
				}
				SourceType source = ref.getSource();
				if (sourceTypesToClear.contains(source)) {
					referenceManager.delete(ref);
				}
			}
			monitor.incrementProgress(1);
		}
	}

	private String getMessage(boolean clearInstructions, boolean clearData) {
		if (!clearData) {
			return "Clearing Instructions...";
		}
		if (!clearInstructions) {
			return "Clearing Data...";
		}
		return "Clearing Instructions and Data...";
	}
}
