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

import java.util.*;

import ghidra.app.plugin.match.MatchSymbol;
import ghidra.app.plugin.match.MatchSymbol.MatchedSymbol;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelator;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SymbolNameProgramCorrelator extends VTAbstractProgramCorrelator {

	private final String name;

	private final boolean oneToOne;

	public SymbolNameProgramCorrelator(ServiceProvider serviceProvider, Program sourceProgram,
			AddressSetView sourceAddressSet, Program destinationProgram,
			AddressSetView destinationAddressSet, ToolOptions options, String name,
			boolean oneToOne) {
		super(serviceProvider, sourceProgram, sourceAddressSet, destinationProgram,
			destinationAddressSet, options);
		this.name = name;
		this.oneToOne = oneToOne;

	}

	@Override
	protected void doCorrelate(VTMatchSet matchSet, TaskMonitor monitor) throws CancelledException {
		int minSymbolNameLength =
			getOptions().getInt(SymbolNameProgramCorrelatorFactory.MIN_SYMBOL_NAME_LENGTH,
				SymbolNameProgramCorrelatorFactory.MIN_SYMBOL_NAME_LENGTH_DEFAULT);

		boolean includeExternals =
			getOptions().getBoolean(SymbolNameProgramCorrelatorFactory.INCLUDE_EXTERNAL_SYMBOLS,
				SymbolNameProgramCorrelatorFactory.INCLUDE_EXTERNAL_SYMBOLS_DEFAULT);

		Collection<MatchedSymbol> matchedSymbols = MatchSymbol.matchSymbol(getSourceProgram(),
			getSourceAddressSet(), getDestinationProgram(), getDestinationAddressSet(),
			minSymbolNameLength, oneToOne, includeExternals, monitor);

		Map<AddressMatch, Integer> matchScoreMap = new HashMap<>();

		monitor.initialize(matchedSymbols.size());
		monitor.setMessage("Deduping " + matchedSymbols.size() + " match objects...");
		int skipAmount = 1000;
		int count = 0;
		for (MatchedSymbol matchedSymbol : matchedSymbols) {
			monitor.checkCanceled();
			++count;
			if (count % skipAmount == 0) {
				monitor.incrementProgress(skipAmount);
			}
			AddressMatch addressMatch = new AddressMatch(matchedSymbol);
			int scoreFactor = matchedSymbol.getMatchCount();
			Integer previousScoreFactor = matchScoreMap.get(addressMatch);
			if (previousScoreFactor == null || scoreFactor < previousScoreFactor) {
				matchScoreMap.put(addressMatch, scoreFactor);
			}
		}

		monitor.initialize(matchScoreMap.size());
		monitor.setMessage("Adding " + matchScoreMap.size() + " match objects...");
		count = 0;
		for (AddressMatch addressMatch : matchScoreMap.keySet()) {
			monitor.checkCanceled();
			++count;
			if (count % skipAmount == 0) {
				monitor.incrementProgress(skipAmount);
			}
			VTMatchInfo match = generateMatchFromMatchedSymbol(matchSet, addressMatch.aAddr,
				addressMatch.bAddr, matchScoreMap.get(addressMatch), addressMatch.matchType);
			matchSet.addMatch(match);
		}
	}

	/**
	 * This class contains the escense of a symbol match which does not preserve 
	 * the actual symbol but only its location and match-type (DATA or FUNCTION).
	 * This class is used to aid the deduping of matches produced by a symbol
	 * correlator.
	 */
	private static class AddressMatch {
		final SymbolType matchType;
		final Address aAddr;
		final Address bAddr;

		AddressMatch(MatchedSymbol matchedSymbol) {
			this.matchType = matchedSymbol.getMatchType();
			this.aAddr = matchedSymbol.getASymbolAddress();
			this.bAddr = matchedSymbol.getBSymbolAddress();
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + aAddr.hashCode();
			result = prime * result + bAddr.hashCode();
			result = prime * result + matchType.hashCode();
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (!(obj instanceof AddressMatch)) {
				return false;
			}
			AddressMatch other = (AddressMatch) obj;
			return aAddr.equals(other.aAddr) && bAddr.equals(other.bAddr) &&
				matchType.equals(other.matchType);
		}

	}

	private VTMatchInfo generateMatchFromMatchedSymbol(VTMatchSet matchSet, Address sourceAddress,
			Address destinationAddress, int scoreFactor, SymbolType matchType) {

		int sourceLength;
		int destinationLength;
		VTAssociationType associationType;

		VTScore similarity = new VTScore(1.000);
		VTScore confidence = new VTScore(10.0 / scoreFactor);

		if (matchType == SymbolType.FUNCTION) {
			Function sourceFunction =
				getSourceProgram().getFunctionManager().getFunctionAt(sourceAddress);
			Function destinationFunction =
				getDestinationProgram().getFunctionManager().getFunctionAt(destinationAddress);

			sourceLength = (int) sourceFunction.getBody().getNumAddresses();
			destinationLength = (int) destinationFunction.getBody().getNumAddresses();
			associationType = VTAssociationType.FUNCTION;
		}
		else {
			Data sourceData = getSourceProgram().getListing().getDataAt(sourceAddress);
			Data destinationData =
				getDestinationProgram().getListing().getDataAt(destinationAddress);

			sourceLength = sourceData.getLength();
			destinationLength = destinationData.getLength();
			associationType = VTAssociationType.DATA;
		}

		VTMatchInfo match = new VTMatchInfo(matchSet);

		match.setSimilarityScore(similarity);
		match.setConfidenceScore(confidence);
		match.setSourceLength(sourceLength);
		match.setSourceAddress(sourceAddress);
		match.setDestinationLength(destinationLength);
		match.setDestinationAddress(destinationAddress);
		match.setTag(null);
		match.setAssociationType(associationType);

		return match;
	}

	@Override
	public String getName() {
		return name;
	}
}
