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
package ghidra.app.util.bin.format.dwarf4.next;

import java.io.IOException;
import java.util.Iterator;
import java.util.NoSuchElementException;

import ghidra.app.util.bin.format.dwarf4.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Handles the details of iterating all the {@link DIEAggregate DIEAs} of a DWARF program.
 * <p>
 * DWARF programs are made of multiple compilation units (CUs), and each CU has
 * {@link DebugInfoEntry DIE}s that are grouped together into aggregates (DIEAs).
 * <p>
 * In normal operation, to iterate the DIEAs, each CU's DIEs are loaded into memory,
 * iterated, and then thrown away before going to the next CU.
 * <p>
 * There are typically no DIE references between CUs, but if there are,
 * {@link DWARFImportOptions#isPreloadAllDIEs()} needs to be turned on by the user before
 * analysis begins.
 */
public class DIEAMonitoredIterator {

	/**
	 * Create an iterable to allow for-each usage of this iterator.
	 *
	 * @param prog {@link DWARFProgram} that holds the DIEs.
	 * @param monitorMessage String to display in the TaskMonitor.
	 * @param monitor {@link TaskMonitor}
	 * @return Iterable that can be used in a for-each loop.
	 */
	public static Iterable<DIEAggregate> iterable(DWARFProgram prog, String monitorMessage,
			TaskMonitor monitor) {
		return new Iterable<DIEAggregate>() {
			@Override
			public Iterator<DIEAggregate> iterator() {
				return prog.getImportOptions().isPreloadAllDIEs()
						? new SimpleDIEAMonitoredIterator(prog, monitorMessage, monitor)
						: new PagedDIEAMonitoredIterator(prog, monitorMessage, monitor);
			}
		};
	}

	/**
	 * {@link DIEAggregate} iterator for the "preload all dies" mode.
	 */
	static class SimpleDIEAMonitoredIterator implements Iterator<DIEAggregate> {
		private Iterator<DIEAggregate> aggregateIterator;
		private int aggregateTotalCount;
		private TaskMonitor monitor;
		private String monitorMessage;

		public SimpleDIEAMonitoredIterator(DWARFProgram prog, String monitorMessage,
				TaskMonitor monitor) {
			this.monitor = monitor;
			this.monitorMessage = monitorMessage;
			this.aggregateTotalCount = prog.getTotalAggregateCount();
			this.aggregateIterator = prog.getAggregates().iterator();

			monitor.setIndeterminate(false);
			monitor.setShowProgressValue(true);
			monitor.initialize(aggregateTotalCount);
			monitor.setMessage(monitorMessage);
		}

		@Override
		public boolean hasNext() {
			return aggregateIterator.hasNext();
		}

		@Override
		public DIEAggregate next() {
			if (!hasNext()) {
				throw new NoSuchElementException();
			}
			DIEAggregate diea = aggregateIterator.next();

			monitor.setMaximum(aggregateTotalCount);
			monitor.setMessage(monitorMessage);
			monitor.incrementProgress(1);
			return diea;
		}

	}

	/**
	 * {@link DIEAggregate} iterator for normal, CU-by-CU iteration of DIE records.
	 */
	static class PagedDIEAMonitoredIterator implements Iterator<DIEAggregate> {
		private TaskMonitor monitor;
		private DWARFProgram prog;
		private String monitorMessage;
		private Iterator<DWARFCompilationUnit> cuIterator;
		private DWARFCompilationUnit cu;
		private Iterator<DIEAggregate> aggregateIterator;
		private int cuCount;
		private int aggregateTotalCount;

		public PagedDIEAMonitoredIterator(DWARFProgram prog, String monitorMessage,
				TaskMonitor monitor) {
			this.prog = prog;
			this.monitor = monitor;
			this.monitorMessage = monitorMessage;
			this.cuCount = prog.getCompilationUnits().size();
			this.aggregateTotalCount = prog.getTotalAggregateCount();
			this.cuIterator = prog.getCompilationUnits().iterator();

			monitor.setIndeterminate(false);
			monitor.setShowProgressValue(true);
			monitor.initialize(aggregateTotalCount);
			monitor.setMessage(monitorMessage);
		}

		private void updateMonitorMessage() {
			// monitor's max gets tweaked by other users during analysis, so
			// we reset it here every now and then
			monitor.setMaximum(aggregateTotalCount);
			monitor.setMessage(
				monitorMessage + " - Compilation Unit #" + cu.getCompUnitNumber() + "/" + cuCount);
		}

		private void finalizeMonitorMessage() {
			monitor.setMessage(monitorMessage + " - Done");
		}

		@Override
		public boolean hasNext() {
			while (true) {
				if (aggregateIterator == null) {
					if (cuIterator.hasNext()) {
						cu = cuIterator.next();

						try {
							prog.setCurrentCompilationUnit(cu, monitor);
						}
						catch (IOException | DWARFException e) {
							Msg.warn(this,
								"Error when reading DIE entries for CU #" + cu.getCompUnitNumber(),
								e);
							return false;
						}
						catch (CancelledException e) {
							// no need to emit warning
							return false;
						}
						aggregateIterator = prog.getAggregates().iterator();
						updateMonitorMessage();
					}
					else {
						finalizeMonitorMessage();
						return false;
					}
				}
				if (aggregateIterator.hasNext()) {
					return true;
				}

				// The DIEA iterator for this CU is done.
				// Throw it away (which signals that this CU is done.)  The next
				// loop in this while() will advance to the next CU and its entries.
				aggregateIterator = null;
			}
		}

		@Override
		public DIEAggregate next() {
			if (!hasNext()) {
				throw new NoSuchElementException();
			}
			DIEAggregate diea = aggregateIterator.next();
			monitor.incrementProgress(1);
			return diea;
		}
	}
}
