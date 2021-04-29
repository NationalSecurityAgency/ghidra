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
import ghidra.trace.database.listing.DBTraceCodeRegisterSpace;
import ghidra.trace.database.listing.UndefinedDBTraceData;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.program.TraceProgramViewRegisterListing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DBTraceProgramViewRegisterListing extends AbstractDBTraceProgramViewListing
		implements TraceProgramViewRegisterListing {
	private final DBTraceThread thread;
	private Address minAddr;
	private Address maxAddr;

	public DBTraceProgramViewRegisterListing(DBTraceProgramView program,
			DBTraceCodeRegisterSpace regSpace) {
		super(program, regSpace);
		this.thread = regSpace.getThread();

		AddressSpace space = program.getAddressFactory().getRegisterSpace();
		this.minAddr = space.getMinAddress();
		this.maxAddr = space.getMaxAddress();
	}

	@Override
	public DBTraceThread getThread() {
		return thread;
	}

	@Override
	public UndefinedDBTraceData doCreateUndefinedUnit(Address address) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isUndefined(Address start, Address end) {
		return codeOperations.undefinedData()
				.coversRange(Range.closed(program.snap, program.snap),
					new AddressRangeImpl(start, end));
	}

	@Override
	public void clearCodeUnits(Address startAddr, Address endAddr, boolean clearContext,
			TaskMonitor monitor) throws CancelledException {
		codeOperations.definedUnits()
				.clear(Range.closed(program.snap, program.snap),
					new AddressRangeImpl(startAddr, endAddr), clearContext, monitor);
	}

	@Override
	// TODO: Delete this when the interface removes it
	public void clearAll(boolean clearContext, TaskMonitor monitor) {
		try {
			codeOperations.definedUnits()
					.clear(Range.closed(program.snap, program.snap),
						new AddressRangeImpl(minAddr, maxAddr), clearContext, monitor);
		}
		catch (CancelledException e) {
			// This whole method is supposed to go away, anyway
			throw new AssertionError(e);
		}
	}
}
