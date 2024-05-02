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

import java.util.*;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.AddressCorrelation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class LinearFunctionAddressCorrelation implements AddressCorrelation {

	public static final String NAME = "LinearFunctionAddressCorrelation";

	private Map<Address, AddressRange> cachedForwardAddressMap;
	private final Function sourceFunction;
	private final Function destinationFunction;

	LinearFunctionAddressCorrelation(Function sourceFunction, Function destinationFunction) {
		this.sourceFunction = sourceFunction;
		this.destinationFunction = destinationFunction;
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public AddressRange getCorrelatedDestinationRange(Address sourceAddress, TaskMonitor monitor)
			throws CancelledException {
		initialize(monitor);
		AddressRange toRange = cachedForwardAddressMap.get(sourceAddress);
		if (toRange == null) {
			double percentOffset = findPercentageFromFunctionStart(sourceAddress);
			Address destinationAddress = getDestinationAddress(percentOffset);
			toRange = new AddressRangeImpl(destinationAddress, destinationAddress);
		}
		return toRange;
	}

	private void initialize(TaskMonitor monitor) {
		if (cachedForwardAddressMap == null) {
			cachedForwardAddressMap = new HashMap<Address, AddressRange>();
			computeParamCorrelation();
		}
	}

	private double findPercentageFromFunctionStart(Address address) {
		AddressSetView srcBody = sourceFunction.getBody();

		long accumulatedLength = 0;

		Iterator<AddressRange> iterator = srcBody.iterator();
		while (iterator.hasNext()) {
			AddressRange range = iterator.next();
			if (range.getMaxAddress().compareTo(address) < 0) {
				accumulatedLength += range.getLength();
			}
			else {
				if (range.contains(address)) {
					accumulatedLength += address.subtract(range.getMinAddress());
				}
				break;
			}
		}

		double percentOffset = (double) (accumulatedLength) / srcBody.getNumAddresses();

		return percentOffset;
	}

	private Address getDestinationAddress(double percentOffset) {
		AddressSetView srcBody = destinationFunction.getBody();
		long offset = (long) (percentOffset * srcBody.getNumAddresses() + 0.5);
		AddressRangeIterator addressRanges = srcBody.getAddressRanges();
		while (addressRanges.hasNext()) {
			AddressRange addressRange = addressRanges.next();
			long rangeLength = addressRange.getLength();
			if (offset < rangeLength) {
				Address address = addressRange.getMinAddress().add(offset);
				return address;
			}
			offset -= rangeLength;
		}
		return srcBody.getMaxAddress();
	}

	private void computeParamCorrelation() {
		Parameter[] sourceParameters = sourceFunction.getParameters();
		Parameter[] destinationParameters = destinationFunction.getParameters();
		if (sourceParameters.length != destinationParameters.length) {
			return;
		}
		Map<Address, AddressRange> map = new HashMap<Address, AddressRange>();
		for (int i = 0; i < sourceParameters.length; i++) {
			Parameter sourceParameter = sourceParameters[i];
			Parameter destinationParameter = destinationParameters[i];
			if (!sourceParameter.isValid() || !destinationParameter.isValid()) {
				return;
			}
			VariableStorage sourceParamStorage = sourceParameter.getVariableStorage();
			VariableStorage destParamStorage = destinationParameter.getVariableStorage();
			if (!sourceParamStorage.equals(destParamStorage)) {
				return;
			}
			Address dest = sourceParamStorage.getMinAddress();
			Address src = destParamStorage.getMinAddress();
			map.put(src, new AddressRangeImpl(dest, dest));
		}
		cachedForwardAddressMap.putAll(map);
	}
	
}
