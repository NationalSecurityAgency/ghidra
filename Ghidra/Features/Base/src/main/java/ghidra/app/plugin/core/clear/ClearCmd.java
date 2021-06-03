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

import java.util.Iterator;
import java.util.Set;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class ClearCmd extends BackgroundCommand {
	private static final int EVENT_LIMIT = 1000;

	private AddressSetView view;
	private ClearOptions options;
	private boolean sendIndividualEvents = false;

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
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {

		boolean wasEabled = obj.isSendingEvents();
		try {
			obj.setEventsEnabled(sendIndividualEvents);
			return doApplyTo(obj, monitor);
		}
		finally {
			obj.setEventsEnabled(wasEabled);
		}
	}

	private boolean doApplyTo(DomainObject obj, TaskMonitor monitor) {

		try {
			doApplyWithCancel(obj, monitor);
			monitor.setMessage("Clear completed");
			return true;
		}
		catch (CancelledException e) {
			return true;
		}
	}

	private boolean doApplyWithCancel(DomainObject obj, TaskMonitor monitor)
			throws CancelledException {

		if (monitor == null) {
			monitor = TaskMonitorAdapter.DUMMY_MONITOR;
		}

		Program program = (Program) obj;
		if (options == null) {
			clearCode(program, view, monitor);
			return true;
		}

		if (options.clearEquates()) {
			clearEquates(program, view, monitor);
		}
		if (options.clearCode()) {
			clearCode(program, view, monitor);
		}
		if (options.clearComments()) {
			clearComments(program, view, monitor);
		}
		if (options.clearFunctions()) {
			clearFunctions(program, view, monitor);
		}
		if (options.clearSymbols()) {
			clearSymbols(program, view, monitor);
		}
		if (options.clearProperties()) {
			clearProperties(program, view, monitor);
		}
		if (options.clearRegisters()) {
			clearRegisters(program, view, monitor);
		}
		Set<SourceType> referenceSourceTypesToClear = options.getReferenceSourceTypesToClear();
		if (!options.clearCode() && !referenceSourceTypesToClear.isEmpty()) {
			clearReferences(program, view, referenceSourceTypesToClear, monitor);
		}
		if (options.clearBookmarks()) {
			clearBookmarks(program, view, monitor);
		}
		return true;
	}

	private void clearSymbols(Program program, AddressSetView clearView, TaskMonitor monitor)
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
				monitor.checkCanceled();
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

	private void clearComments(Program program, AddressSetView clearView, TaskMonitor monitor)
			throws CancelledException {

		monitor.initialize(clearView.getNumAddresses());
		monitor.setMessage("Starting to clear comments...");

		Listing listing = program.getListing();
		AddressRangeIterator iter = clearView.getAddressRanges();
		int progress = 0;
		while (iter.hasNext()) {

			monitor.checkCanceled();
			AddressRange range = iter.next();
			listing.clearComments(range.getMinAddress(), range.getMaxAddress());
			progress += range.getLength();
			monitor.setProgress(progress);
		}
	}

	private void clearProperties(Program program, AddressSetView clearView, TaskMonitor monitor)
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

	private void clearFunctions(Program program, AddressSetView clearView, TaskMonitor monitor)
			throws CancelledException {

		FunctionManager manager = program.getFunctionManager();
		int count = manager.getFunctionCount();

		monitor.setMessage("Clearing functions...");
		monitor.initialize(count);

		FunctionIterator iter = manager.getFunctions(clearView, true);
		while (iter.hasNext()) {

			monitor.checkCanceled();
			Function func = iter.next();
			monitor.incrementProgress(1);
			manager.removeFunction(func.getEntryPoint());
		}
	}

	private void clearRegisters(Program program, AddressSetView clearView, TaskMonitor monitor)
			throws CancelledException {

		monitor.initialize(clearView.getNumAddresses());
		monitor.setMessage("Starting to clear registers...");
		ProgramContext pc = program.getProgramContext();
		AddressRangeIterator iter = clearView.getAddressRanges();
		while (iter.hasNext()) {
			AddressRange range = iter.next();
			removeRegisters(pc, range, monitor);
		}
	}

	private void clearEquates(Program p, AddressSetView clearView, TaskMonitor monitor)
			throws CancelledException {
		monitor.initialize(100);
		monitor.setMessage("Starting to clear equates...");

		EquateTable eqtbl = p.getEquateTable();
		Iterator<Equate> iter = eqtbl.getEquates();
		while (iter.hasNext()) {

			monitor.checkCanceled();
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

	private void clearCode(Program program, AddressSetView clearView, TaskMonitor monitor)
			throws CancelledException {

		Listing listing = program.getListing();

		monitor.initialize(clearView.getNumAddresses());
		monitor.setMessage("Starting to clear code...");

		AddressRangeIterator it = clearView.getAddressRanges();
		while (it.hasNext()) {

			AddressRange currentRange = it.next();
			Address start = currentRange.getMinAddress();
			Address end = currentRange.getMaxAddress();
			clearAddresses(monitor, listing, start, end);
		}
	}

	private void clearAddresses(TaskMonitor monitor, Listing listing, Address start, Address end)
			throws CancelledException {

		boolean clearContext = options != null && options.clearRegisters();
		AddressRangeChunker chunker = new AddressRangeChunker(start, end, 10000);
		for (AddressRange range : chunker) {

			Address min = range.getMinAddress();
			Address max = range.getMaxAddress();

			monitor.setMessage("Clearing code at " + min);

			listing.clearCodeUnits(min, max, clearContext, monitor);

			int numDone = (int) (max.subtract(min) + 1);
			monitor.incrementProgress(numDone);

			// Allow the Swing thread a chance to paint components that may require a DB lock
			Swing.allowSwingToProcessEvents();
		}
	}

	private void clearReferences(Program program, AddressSetView clearView,
			Set<SourceType> sourceTypesToClear, TaskMonitor monitor) throws CancelledException {

		if (clearView.isEmpty()) {
			return;
		}

		monitor.initialize(clearView.getNumAddresses());
		monitor.setMessage("Clearing references...");

		ReferenceManager refMgr = program.getReferenceManager();
		AddressIterator it = refMgr.getReferenceSourceIterator(clearView, true);
		removeRefs(refMgr, it, sourceTypesToClear, monitor);
	}

	private void clearBookmarks(Program program, AddressSetView clearView, TaskMonitor monitor)
			throws CancelledException {

		if (clearView.isEmpty()) {
			return;
		}
		monitor.initialize(clearView.getNumAddresses());
		monitor.setMessage("Clearing bookmarks...");

		BookmarkManager bookmarkMgr = program.getBookmarkManager();
		bookmarkMgr.removeBookmarks(clearView, monitor);
	}

	private void removeRegisters(ProgramContext pc, AddressRange range, TaskMonitor monitor)
			throws CancelledException {
		for (Register reg : pc.getRegistersWithValues()) {
			monitor.checkCanceled();

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

	private void removeRefs(ReferenceManager refMgr, AddressIterator iter,
			Set<SourceType> sourceTypesToClear, TaskMonitor monitor) throws CancelledException {
		while (iter.hasNext()) {

			monitor.checkCanceled();

			Address addr = iter.next();
			Reference[] refs = refMgr.getReferencesFrom(addr);
			for (Reference ref : refs) {
				if (monitor.isCancelled()) {
					break;
				}
				SourceType source = ref.getSource();
				if (sourceTypesToClear.contains(source)) {
					refMgr.delete(ref);
				}
			}
			monitor.incrementProgress(1);
		}
	}
}
