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
package ghidra.trace.database.program;

import com.google.common.collect.Range;

import ghidra.program.model.address.*;
import ghidra.util.LockHold;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DBTraceProgramViewListing extends AbstractDBTraceProgramViewListing {
	protected final AddressSet allMemory;

	public DBTraceProgramViewListing(DBTraceProgramView program) {
		super(program, program.trace.getCodeManager());
		this.allMemory = program.getAddressFactory().getAddressSet();
	}

	@Override
	public boolean isUndefined(Address start, Address end) {
		try (LockHold hold = program.trace.lockRead()) {
			for (AddressRange range : program.getAddressFactory().getAddressSet(start, end)) {
				for (long s : program.viewport.getOrderedSnaps()) {
					if (!isUndefinedRange(s, range)) {
						return false;
					}
				}
			}
			return true;
		}
	}

	@Override
	public void clearCodeUnits(Address startAddr, Address endAddr, boolean clearContext,
			TaskMonitor monitor) throws CancelledException {
		try (LockHold hold = program.trace.lockWrite()) {
			for (AddressRange range : program.getAddressFactory()
					.getAddressSet(startAddr,
						endAddr)) {
				monitor.checkCanceled();
				codeOperations.definedUnits()
						.clear(Range.closed(program.snap, program.snap), range,
							clearContext, monitor);
			}
		}
	}

	@Override
	// TODO: Delete this when the interface removes it
	public void clearAll(boolean clearContext, TaskMonitor monitor) {
		try (LockHold hold = program.trace.lockRead()) {
			for (AddressRange range : allMemory) {
				codeOperations.definedUnits()
						.clear(Range.closed(program.snap, program.snap), range,
							clearContext, monitor);
			}
		}
		catch (CancelledException e) {
			// This whole method is supposed to go away, anyway
			throw new AssertionError(e);
		}
	}
}
