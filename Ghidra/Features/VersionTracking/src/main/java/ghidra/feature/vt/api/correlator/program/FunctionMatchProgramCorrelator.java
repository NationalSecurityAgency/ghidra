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
package ghidra.feature.vt.api.correlator.program;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.plugin.match.FunctionHasher;
import ghidra.app.plugin.match.MatchFunctions;
import ghidra.app.plugin.match.MatchFunctions.MatchedFunctions;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelator;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class FunctionMatchProgramCorrelator extends VTAbstractProgramCorrelator {
	private final String name;

	private final boolean oneToOne;
	private final FunctionHasher hasher;

	public FunctionMatchProgramCorrelator(ServiceProvider serviceProvider, Program sourceProgram,
			AddressSetView sourceAddressSet, Program destinationProgram,
			AddressSetView destinationAddressSet, ToolOptions options, String name,
			boolean oneToOne, FunctionHasher hasher) {
		super(serviceProvider, sourceProgram, sourceAddressSet, destinationProgram,
			destinationAddressSet, options);
		this.name = name;
		this.oneToOne = oneToOne;
		this.hasher = hasher;
	}

	@Override
	protected void doCorrelate(VTMatchSet matchSet, TaskMonitor monitor) throws CancelledException {
		int functionMinimumSize = getOptions().getInt(
			ExactMatchInstructionsProgramCorrelatorFactory.FUNCTION_MINIMUM_SIZE,
			ExactMatchInstructionsProgramCorrelatorFactory.FUNCTION_MINIMUM_SIZE_DEFAULT);

		List<MatchedFunctions> matchedFunctions = MatchFunctions.matchFunctions(getSourceProgram(),
			getSourceAddressSet(), getDestinationProgram(), getDestinationAddressSet(),
			functionMinimumSize, oneToOne, !oneToOne, hasher, monitor);

		monitor.setMessage("Scoring " + matchedFunctions.size() + " matches...");
		monitor.initialize(matchedFunctions.size());
		List<VTMatchInfo> results = new ArrayList<VTMatchInfo>();
		for (MatchedFunctions matchedFunction : matchedFunctions) {
			if (monitor.isCancelled()) {
				return;
			}
			monitor.incrementProgress(1);
			VTMatchInfo matchInfo =
				generateMatchFromMatchedFunctions(matchSet, matchedFunction, monitor);
			if (matchInfo != null) {
				results.add(matchInfo);
			}
		}

		monitor.setMessage("Adding " + results.size() + " match objects...");
		monitor.initialize(results.size());
		for (VTMatchInfo info : results) {
			if (monitor.isCancelled()) {
				return;
			}
			monitor.incrementProgress(1);
			matchSet.addMatch(info);
		}
	}

	private VTMatchInfo generateMatchFromMatchedFunctions(VTMatchSet matchSet,
			MatchedFunctions matchedFunction, TaskMonitor monitor) {

		Address sourceAddress = matchedFunction.getAFunctionAddress();
		Address destinationAddress = matchedFunction.getBFunctionAddress();
		VTScore similarity = new VTScore(1.0);
		VTScore confidence =
			new VTScore(10.0 / (matchedFunction.getBMatchNum() * matchedFunction.getAMatchNum()));

		Function sourceFunction =
			getSourceProgram().getFunctionManager().getFunctionAt(sourceAddress);
		Function destinationFunction =
			getDestinationProgram().getFunctionManager().getFunctionAt(destinationAddress);
		int sourceLength = (int) sourceFunction.getBody().getNumAddresses();
		int destinationLength = (int) destinationFunction.getBody().getNumAddresses();

		if (sourceLength != destinationLength) {
			return null;
		}

		VTMatchInfo matchInfo = new VTMatchInfo(matchSet);

		matchInfo.setSimilarityScore(similarity);
		matchInfo.setConfidenceScore(confidence);
		matchInfo.setSourceLength(sourceLength);
		matchInfo.setDestinationLength(destinationLength);
		matchInfo.setSourceAddress(sourceAddress);
		matchInfo.setDestinationAddress(destinationAddress);
		matchInfo.setTag(null);
		matchInfo.setAssociationType(VTAssociationType.FUNCTION);

		return matchInfo;
	}

	@Override
	public String getName() {
		return name;
	}
}
