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

import java.util.List;
import java.util.Set;

import ghidra.app.decompiler.ClangToken;
import ghidra.codecompare.graphanalysis.TokenBin;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class DetermineDecompilerDifferencesTask extends Task {

	private boolean matchConstantsExactly;

	private DiffClangHighlightController leftHighlightController;
	private DiffClangHighlightController rightHighlightController;

	private DecompileDataDiff decompileDataDiff;

	private CodeDiffFieldPanelCoordinator decompilerFieldPanelCoordinator;

	public DetermineDecompilerDifferencesTask(DecompileDataDiff decompileDataDiff,
			boolean matchConstantsExactly, DiffClangHighlightController leftHighlightController,
			DiffClangHighlightController rightHighlightController,
			CodeDiffFieldPanelCoordinator decompilerFieldPanelCoordinator) {

		super("Mapping C Tokens Between Functions", true, true, true);
		this.decompileDataDiff = decompileDataDiff;
		this.matchConstantsExactly = matchConstantsExactly;
		this.leftHighlightController = leftHighlightController;
		this.rightHighlightController = rightHighlightController;
		this.decompilerFieldPanelCoordinator = decompilerFieldPanelCoordinator;
	}

	@Override
	public void run(TaskMonitor monitor) {
		monitor.setMessage(
			(matchConstantsExactly ? "Function Token Mapping By Matching Constants Exactly..."
					: "Function Token Mapping WITHOUT Matching Constants Exactly..."));
		try {
			determineDifferences(monitor);
		}
		catch (CancelledException e) {
			// User Cancelled.
		}
	}

	synchronized void determineDifferences(TaskMonitor monitor) throws CancelledException {

		List<TokenBin> highBins = decompileDataDiff.getTokenMap(matchConstantsExactly, monitor);
		Set<ClangToken> leftHighlightTokenSet =
			decompileDataDiff.getLeftHighlightTokenSet(matchConstantsExactly, monitor);
		Set<ClangToken> rightHighlightTokenSet =
			decompileDataDiff.getRightHighlightTokenSet(matchConstantsExactly, monitor);

		leftHighlightController.setDiffHighlights(highBins, leftHighlightTokenSet);
		rightHighlightController.setDiffHighlights(highBins, rightHighlightTokenSet);

		decompilerFieldPanelCoordinator.replaceDecompileDataDiff(decompileDataDiff,
			matchConstantsExactly, monitor);
	}

}
