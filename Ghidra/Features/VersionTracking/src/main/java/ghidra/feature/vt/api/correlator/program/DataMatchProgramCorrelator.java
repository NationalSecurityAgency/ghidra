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

import ghidra.app.plugin.match.MatchData;
import ghidra.app.plugin.match.MatchedData;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelator;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.List;

public class DataMatchProgramCorrelator extends VTAbstractProgramCorrelator {
	private final String name;

	private final boolean oneToOne;

	public DataMatchProgramCorrelator(ServiceProvider serviceProvider, Program sourceProgram,
			AddressSetView sourceAddressSet, Program destinationProgram,
			AddressSetView destinationAddressSet, ToolOptions options, String name, boolean oneToOne) {
		super(serviceProvider, sourceProgram, sourceAddressSet, destinationProgram,
			destinationAddressSet, options);
		this.name = name;
		this.oneToOne = oneToOne;
	}

	@Override
	protected void doCorrelate(VTMatchSet matchSet, TaskMonitor monitor) throws CancelledException {
		int dataMinimumSize =
			getOptions().getInt(ExactDataMatchProgramCorrelatorFactory.DATA_MINIMUM_SIZE,
				ExactDataMatchProgramCorrelatorFactory.DATA_MINIMUM_SIZE_DEFAULT);
		int dataMaximumSize =
			getOptions().getInt(ExactDataMatchProgramCorrelatorFactory.DATA_MAXIMUM_SIZE,
				ExactDataMatchProgramCorrelatorFactory.DATA_MAXIMUM_SIZE_DEFAULT);
		int dataAlignment =
			getOptions().getInt(ExactDataMatchProgramCorrelatorFactory.DATA_ALIGNMENT,
				ExactDataMatchProgramCorrelatorFactory.DATA_ALIGNMENT_DEFAULT);
		boolean skipHomogenousData =
			getOptions().getBoolean(ExactDataMatchProgramCorrelatorFactory.SKIP_HOMOGENOUS_DATA,
				ExactDataMatchProgramCorrelatorFactory.SKIP_HOMOGENOUS_DATA_DEFAULT);

		List<MatchedData> matchedDataList =
			MatchData.matchData(getSourceProgram(), getSourceAddressSet(), getDestinationProgram(),
				getDestinationAddressSet(), dataMinimumSize, dataMaximumSize, dataAlignment,
				skipHomogenousData, oneToOne, !oneToOne, monitor);

		monitor.initialize(matchedDataList.size());
		monitor.setMessage("Finally, adding " + matchedDataList.size() + " match objects...");
		final int skipAmount = 1000;
		int count = 0;
		for (MatchedData matchedData : matchedDataList) {
			++count;
			if (count % skipAmount == 0) {
				if (monitor.isCancelled()) {
					break;
				}
				monitor.incrementProgress(skipAmount);
			}
			VTMatchInfo matchInfo = generateMatchFromMatchedData(matchSet, matchedData);
			matchSet.addMatch(matchInfo);
		}
	}

	private VTMatchInfo generateMatchFromMatchedData(VTMatchSet matchSet, MatchedData matchedData) {

		Address sourceAddress = matchedData.getADataAddress();
		Address destinationAddress = matchedData.getBDataAddress();

		VTScore similarity = new VTScore(1.000);
		VTScore confidence =
			new VTScore(10.0 / (matchedData.getBMatchNum() * matchedData.getAMatchNum()));

		Data sourceData = matchedData.getAData();
		int sourceLength = sourceData.getLength();

		VTMatchInfo matchInfo = new VTMatchInfo(matchSet);

		matchInfo.setSimilarityScore(similarity);
		matchInfo.setConfidenceScore(confidence);
		matchInfo.setSourceLength(sourceLength);
		//yes I meant to put sourceLength here
		// if dest data is defined it has to be same length to get here
		// if not defined, it has to be same length or it wouldn't have matched in the first place
		matchInfo.setSourceAddress(sourceAddress);
		matchInfo.setDestinationLength(sourceLength);
		matchInfo.setDestinationAddress(destinationAddress);
		matchInfo.setTag(null);
		matchInfo.setAssociationType(VTAssociationType.DATA);

		return matchInfo;
	}

	@Override
	public String getName() {
		return name;
	}
}
