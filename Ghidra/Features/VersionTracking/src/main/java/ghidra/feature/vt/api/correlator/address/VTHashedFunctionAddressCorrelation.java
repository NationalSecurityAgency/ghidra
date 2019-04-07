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
package ghidra.feature.vt.api.correlator.address;

import ghidra.program.model.address.*;
import ghidra.program.model.correlate.HashedFunctionAddressCorrelation;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.AddressCorrelation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Wraps the HashedFunctionAddressCorrelation so that it can be used with version tracking.
 * This correlation attempts to provide a 1-1 map between the instructions of two similar functions.
 * @see HashedFunctionAddressCorrelation
 */
public class VTHashedFunctionAddressCorrelation implements AddressCorrelation {

	public static final String NAME = "VTHashedFunctionAddressCorrelation";

	private final Function sourceFunction;
	private final Function destinationFunction;
	private HashedFunctionAddressCorrelation addressCorrelation;

	/**
	 * Constructs an address correlation between two functions.
	 * @param sourceFunction the source function
	 * @param destinationFunction the destination function
	 */
	public VTHashedFunctionAddressCorrelation(Function sourceFunction, Function destinationFunction) {
		this.sourceFunction = sourceFunction;
		this.destinationFunction = destinationFunction;
		addressCorrelation = null;
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public AddressRange getCorrelatedDestinationRange(Address sourceAddress, TaskMonitor monitor)
			throws CancelledException {
		try {
			initializeCorrelation(monitor);
			Address destinationAddress = addressCorrelation.getAddressInSecond(sourceAddress);
			if (destinationAddress == null) {
				return null; // No matching destination.
			}
			return new AddressRangeImpl(destinationAddress, destinationAddress);
		}
		catch (MemoryAccessException e) {
			Msg.error(this, "Could not create HashedFunctionAddressCorrelation", e);
			return null;
		}
	}

	/**
	 * Creates the HashedFunctionAddressCorrelation that is used by this class if it doesn't 
	 * yet exist.
	 * @param monitor a status monitor for feedback and cancellation while the address correlation 
	 * between the two functions is determined.
	 * @throws CancelledException if the user cancels
	 * @throws MemoryAccessException if either function's memory can't be accessed.
	 */
	private void initializeCorrelation(TaskMonitor monitor) throws CancelledException,
			MemoryAccessException {
		if (addressCorrelation != null) {
			return;
		}
		addressCorrelation =
				new HashedFunctionAddressCorrelation(sourceFunction, destinationFunction,
				monitor);
	}
}
