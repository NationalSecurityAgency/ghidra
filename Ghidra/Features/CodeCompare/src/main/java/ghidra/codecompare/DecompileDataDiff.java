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
package ghidra.codecompare;

import java.util.ArrayList;
import java.util.HashSet;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompileData;
import ghidra.codecompare.graphanalysis.Pinning;
import ghidra.codecompare.graphanalysis.TokenBin;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Class that takes decompile data for two functions (referred to as the left and right functions) 
 * and determines the differences between them.
 */
public class DecompileDataDiff {

	/**
	 * Pairing information for a single configuration of the Pinning algorithm, including:
	 * A list of all TokenBins across both functions that can be paired with each other
	 * (individual TokenBins are marked with their pair, if it exists).
	 * A list of tokens that do not have a match in the left function.
	 * A list of tokens that do not have a match in the right function.
	 */
	private static class Configuration {
		ArrayList<TokenBin> highBins;					// List of all token bins
		HashSet<ClangToken> leftHighlightTokenSet;		// Tokens without a match in the left function
		HashSet<ClangToken> rightHighlightTokenSet;		// Tokens without a match in the right function

		public Configuration(ArrayList<TokenBin> highBins, HighFunction leftFunc,
				HighFunction rightFunc) {
			this.highBins = highBins;
			leftHighlightTokenSet = new HashSet<>();
			rightHighlightTokenSet = new HashSet<>();
			for (TokenBin bin : highBins) {
				if (bin.getMatch() == null) {
					for (ClangToken token : bin) {
						ClangFunction clangFunction = token.getClangFunction();
						HighFunction highFunction = clangFunction.getHighFunction();
						if (leftFunc == highFunction) {
							leftHighlightTokenSet.add(token);
						}
						else if (rightFunc == highFunction) {
							rightHighlightTokenSet.add(token);
						}
					}
				}
			}

		}
	}

	private DecompileData[] decompileData = new DecompileData[2];
	private ClangTokenGroup[] markup = new ClangTokenGroup[2];
	private HighFunction[] hfunc = new HighFunction[2];
	private boolean sizeCollapse;			// True if we are comparing different size architectures

	// Different ways to configure the pinning algorithm
	private static int NOT_EXACT_MATCH_CONSTANTS = 0;
	private static int EXACT_MATCH_CONSTANTS = 1;

	private Configuration[] pairing;		// Token pairing info from different Pinning configurations

	public DecompileDataDiff(DecompileData decompileData1, DecompileData decompileData2) {
		this.decompileData[0] = decompileData1;
		this.decompileData[1] = decompileData2;
		int size1 = decompileData1.getProgram().getLanguage().getLanguageDescription().getSize();
		int size2 = decompileData2.getProgram().getLanguage().getLanguageDescription().getSize();
		sizeCollapse = (size1 != size2);

		markup[0] = decompileData[0].getCCodeMarkup();
		markup[1] = decompileData[1].getCCodeMarkup();

		hfunc[0] = decompileData[0].getHighFunction();
		hfunc[1] = decompileData[1].getHighFunction();
		pairing = new Configuration[2];
	}

	/**
	 * Get sets of tokens (TokenBins) that have been paired across the two functions.
	 * The pairing can be performed either forcing constants to match, or not.
	 * @param matchConstantsExactly is true if constants should be forced to match
	 * @param monitor is the TaskMonitor
	 * @return the list of TokenBins
	 * @throws CancelledException if the user cancels the task
	 */
	public ArrayList<TokenBin> getTokenMap(boolean matchConstantsExactly, TaskMonitor monitor)
			throws CancelledException {

		int index = matchConstantsExactly ? EXACT_MATCH_CONSTANTS : NOT_EXACT_MATCH_CONSTANTS;

		if (pairing[index] == null) {
			Pinning pin = Pinning.makePinning(hfunc[0], hfunc[1], matchConstantsExactly,
				sizeCollapse, true, monitor);
			ArrayList<TokenBin> highBins = pin.buildTokenMap(markup[0], markup[1]);
			pairing[index] = new Configuration(highBins, hfunc[0], hfunc[1]);
		}

		return pairing[index].highBins;
	}

	public HashSet<ClangToken> getLeftHighlightTokenSet(boolean matchConstantsExactly,
			TaskMonitor monitor) throws CancelledException {

		int index = matchConstantsExactly ? EXACT_MATCH_CONSTANTS : NOT_EXACT_MATCH_CONSTANTS;

		if (pairing[index] == null) {
			getTokenMap(matchConstantsExactly, monitor);
		}

		return pairing[index].leftHighlightTokenSet;
	}

	public HashSet<ClangToken> getRightHighlightTokenSet(boolean matchConstantsExactly,
			TaskMonitor monitor) throws CancelledException {

		int matchConstantsIndex =
			matchConstantsExactly ? EXACT_MATCH_CONSTANTS : NOT_EXACT_MATCH_CONSTANTS;

		if (pairing[matchConstantsIndex] == null) {
			getTokenMap(matchConstantsExactly, monitor);
		}

		return pairing[matchConstantsIndex].rightHighlightTokenSet;
	}

	/**
	 * Gets the decompiled high level function for the left function.
	 * @return the left high level function
	 */
	public HighFunction getLeftHighFunction() {
		return hfunc[0];
	}

	/**
	 * Gets the decompiled high level function for the right function.
	 * @return the right high level function
	 */
	public HighFunction getRightHighFunction() {
		return hfunc[1];
	}
}
