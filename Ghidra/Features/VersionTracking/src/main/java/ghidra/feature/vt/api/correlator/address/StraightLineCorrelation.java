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
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Generate address correlations by viewing each function as a list of instructions in address order
 * Instructions are paired one at a time, in order, if the mnemonics of the instructions match.
 * The correlation gives up at the first mismatch.
 * 
 * This algorithm is suitable for correlating functions paired by "exact match" program correlations, where
 * we know apriori that the functions are identical, instruction for instruction.
 *
 */
public class StraightLineCorrelation implements AddressCorrelation {

	public static final String NAME = "StraightLineCorrelation";

	private Map<Address, AddressRange> cachedForwardAddressMap;
	private final Function sourceFunction;
	private final Function destinationFunction;

	public StraightLineCorrelation(Function sourceFunction, Function destinationFunction) {
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
		return cachedForwardAddressMap.get(sourceAddress);
	}

	private void initialize(TaskMonitor monitor) throws CancelledException {
		
		if (cachedForwardAddressMap != null) return;		
		cachedForwardAddressMap = new HashMap<Address, AddressRange>();

		AddressSetView sourceAddressSet = (sourceFunction != null) ? sourceFunction.getBody() : null;
		AddressSetView destinationAddressSet = (destinationFunction != null) ? destinationFunction.getBody() : null;

		if (sourceAddressSet == null || destinationAddressSet == null) 
			return;

		CodeUnitIterator srcIter = sourceFunction.getProgram().getListing().getCodeUnits(sourceAddressSet, true);
		CodeUnitIterator destIter = destinationFunction.getProgram().getListing().getCodeUnits(destinationAddressSet, true);

		monitor.setMessage("Defining address ranges...");
		monitor.initialize(sourceAddressSet.getNumAddresses());
		while(srcIter.hasNext() && destIter.hasNext()) {
			CodeUnit srcCodeUnit = srcIter.next();
			CodeUnit destCodeUnit = destIter.next();
			String srcMnemonic = srcCodeUnit.getMnemonicString();
			String destMnemonic = destCodeUnit.getMnemonicString();
			if (srcMnemonic.equals(destMnemonic)) {
				monitor.checkCanceled();
				monitor.incrementProgress(srcCodeUnit.getLength());
				defineRange(cachedForwardAddressMap, srcCodeUnit, destCodeUnit);				
			}
			else
				break;			// First mismatch we break out of the loop
		}
		computeParamCorrelation();
	}

	/**
	 * Add address correlations for the parameters.
	 */
	protected void computeParamCorrelation() {
		int sourceCount = sourceFunction.getParameterCount();
		int destinationCount = destinationFunction.getParameterCount();
		Parameter[] sourceParameters = sourceFunction.getParameters();
		Parameter[] destinationParameters = destinationFunction.getParameters();
		boolean allMatch = false;
		Map<Address, AddressRange> map = new HashMap<Address, AddressRange>();
		if (sourceCount == destinationCount) {
			allMatch = true;
			for (int i = 0; i < sourceParameters.length; i++) {
				Parameter sourceParameter = sourceParameters[i];
				Parameter destinationParameter = destinationParameters[i];
				DataType sourceDataType = sourceParameter.getDataType();
				DataType destinationDataType = destinationParameter.getDataType();
				int sourceLength = sourceDataType.getLength();
				int destinationLength = destinationDataType.getLength();
				Address dest = destinationParameter.getMinAddress();
				map.put(sourceParameter.getMinAddress(), new AddressRangeImpl(dest, dest));
				if (sourceLength != destinationLength) {
					allMatch = false;
					break;
				}
			}
		}
		if (allMatch) {
			cachedForwardAddressMap.putAll(map);
		}
	}

	/**
	 * Save address correlation between two code units to the map
	 * @param map is the address map
	 * @param sourceCodeUnit is the source code unit
	 * @param destinationCodeUnit is the matching destination code unit
	 */
	private static void defineRange(Map<Address, AddressRange> map,
			CodeUnit sourceCodeUnit, CodeUnit destinationCodeUnit) {
		Address minAddress = sourceCodeUnit.getMinAddress();
		Address maxAddress = sourceCodeUnit.getMaxAddress();
		AddressRangeImpl toRange =
			new AddressRangeImpl(destinationCodeUnit.getMinAddress(),
				destinationCodeUnit.getMaxAddress());
		while (!minAddress.equals(maxAddress)) {
			map.put(minAddress, toRange);
			minAddress = minAddress.next();
		}
		map.put(maxAddress, toRange);
	}
}
