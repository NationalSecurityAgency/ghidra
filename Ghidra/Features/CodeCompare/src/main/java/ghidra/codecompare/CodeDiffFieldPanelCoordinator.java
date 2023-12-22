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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualHashBidiMap;

import docking.widgets.fieldpanel.support.ViewerPosition;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.decompiler.component.DualDecompilerFieldPanelCoordinator;
import ghidra.codecompare.graphanalysis.TokenBin;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Class to coordinate the scrolling of two decompiler panels as well as cursor location 
 * highlighting due to cursor location changes.
 */
public class CodeDiffFieldPanelCoordinator extends DualDecompilerFieldPanelCoordinator {

	private BidiMap<Integer, Integer> leftToRightLineNumberPairing;
	private List<ClangLine> leftLines = new ArrayList<ClangLine>();
	private List<ClangLine> rightLines = new ArrayList<ClangLine>();
	private int lockedLeftLineNumber = 0;
	private int lockedRightLineNumber = 0;
	private DecompilerPanel leftDecompilerPanel;
	private DecompilerPanel rightDecompilerPanel;
	private boolean matchConstantsExactly;
	private List<TokenBin> highBins;

	/**
	 * Constructor
	 * @param dualDecompilerPanel decomp comparison panel
	 */
	public CodeDiffFieldPanelCoordinator(DecompilerDiffCodeComparisonPanel dualDecompilerPanel) {
		super(dualDecompilerPanel);
		this.leftDecompilerPanel = dualDecompilerPanel.getLeftDecompilerPanel();
		this.rightDecompilerPanel = dualDecompilerPanel.getRightDecompilerPanel();
		leftToRightLineNumberPairing = new DualHashBidiMap<>();
	}

	/**
	 * Computes the line pairing for two decompiled functions.  Any existing line pairing is
	 * cleared.
	 * 
	 * @param decompileDataDiff decomp diff
	 * @param monitor monitor
	 * @throws CancelledException if user cancels
	 */
	public void computeLinePairing(DecompileDataDiff decompileDataDiff, TaskMonitor monitor)
			throws CancelledException {
		highBins = decompileDataDiff.getTokenMap(matchConstantsExactly, monitor);
		HighFunction leftHighFunction = decompileDataDiff.getLeftHighFunction();

		clearLineNumberPairing();
		for (TokenBin bin : highBins) {
			if (bin.getMatch() != null) {
				boolean isLeftBin = bin.getHighFunction().equals(leftHighFunction);
				ClangToken binToken = bin.get(0);
				ClangToken sidekickToken = bin.getMatch().get(0);
				ClangToken leftClangToken = isLeftBin ? binToken : sidekickToken;
				ClangToken rightClangToken = isLeftBin ? sidekickToken : binToken;
				ClangLine leftLine = leftClangToken.getLineParent();
				ClangLine rightLine = rightClangToken.getLineParent();
				leftToRightLineNumberPairing.put(leftLine.getLineNumber(),
					rightLine.getLineNumber());
			}
		}
	}

	@Override
	public void leftLocationChanged(ProgramLocation leftLocation) {
		DecompilerLocation leftDecompilerLocation = (DecompilerLocation) leftLocation;

		// Get the line from the token so we can match it with the line from the other panel.
		ClangToken leftToken =
			(leftDecompilerLocation != null) ? leftDecompilerLocation.getToken() : null;
		ClangLine leftLine = (leftToken != null) ? leftToken.getLineParent() : null;
		if (leftLine != null) {
			int leftLineNumber = leftLine.getLineNumber();
			if (searchLeftForPair(leftLineNumber)) {
				lockLines(BigInteger.valueOf(lockedLeftLineNumber),
					BigInteger.valueOf(lockedRightLineNumber));
			}
		}
		panelViewChanged(leftDecompilerPanel);
	}

	@Override
	public void rightLocationChanged(ProgramLocation rightLocation) {
		DecompilerLocation rightDecompilerLocation = (DecompilerLocation) rightLocation;

		// Get the line from the token so we can try to match it with the line from the other panel.
		ClangToken rightToken =
			(rightDecompilerLocation != null) ? rightDecompilerLocation.getToken() : null;
		ClangLine rightLine = (rightToken != null) ? rightToken.getLineParent() : null;
		if (rightLine != null) {
			int rightLineNumber = rightLine.getLineNumber();
			if (searchRightForPair(rightLineNumber)) {
				lockLines(BigInteger.valueOf(lockedLeftLineNumber),
					BigInteger.valueOf(lockedRightLineNumber));
			}
		}
		panelViewChanged(rightDecompilerPanel);
	}

	/**
	 * 
	 * Updates the comparison panel using {@code decompileDataDiff}
	 * 
	 * @param decompileDataDiff decomp diff data
	 * @param shouldMatchConstantsExactly if differences in constant values should count
	 * @param monitor monitor
	 * @throws CancelledException if user cancels
	 */
	public void replaceDecompileDataDiff(DecompileDataDiff decompileDataDiff,
			boolean shouldMatchConstantsExactly, TaskMonitor monitor) throws CancelledException {

		this.matchConstantsExactly = shouldMatchConstantsExactly;
		if (leftDecompilerPanel != null) {
			leftLines = leftDecompilerPanel.getLines();
		}
		else {
			leftLines.clear();
		}

		if (rightDecompilerPanel != null) {
			rightLines = rightDecompilerPanel.getLines();
		}
		else {
			rightLines.clear();
		}
		lockFunctionSignatureLines();
		computeLinePairing(decompileDataDiff, monitor);
	}

	/**
	 * Clears the existing line number pairing
	 */
	void clearLineNumberPairing() {
		leftToRightLineNumberPairing.clear();
	}

	List<TokenBin> getHighBins() {
		return highBins;
	}

	private void panelViewChanged(DecompilerPanel panel) {
		ViewerPosition viewerPosition = panel.getViewerPosition();
		BigInteger index = viewerPosition.getIndex();
		int xOffset = viewerPosition.getXOffset();
		int yOffset = viewerPosition.getYOffset();
		viewChanged(panel.getFieldPanel(), index, xOffset, yOffset);
	}

	//locks the two function signature lines - used when first displaying the comparison
	private void lockFunctionSignatureLines() {

		ClangLine leftLine = getClangLine(leftLines, 0);
		ClangLine rightLine = getClangLine(rightLines, 0);

		// If we can find both lines with function signatures then lock lines on them.
		ClangLine leftFunctionLine = findFunctionSignatureLine(leftLines);
		ClangLine rightFunctionLine = findFunctionSignatureLine(rightLines);
		if (leftFunctionLine != null && rightFunctionLine != null) {
			leftLine = leftFunctionLine;
			rightLine = rightFunctionLine;
		}

		if (leftLine != null && rightLine != null) {
			setLockedLineNumbers(leftLine.getLineNumber(), rightLine.getLineNumber());
			lockLines(BigInteger.valueOf(lockedLeftLineNumber),
				BigInteger.valueOf(lockedRightLineNumber));
		}
	}

	private ClangLine findFunctionSignatureLine(List<ClangLine> lines) {
		for (ClangLine clangLine : lines) {
			int numTokens = clangLine.getNumTokens();
			for (int i = 0; i < numTokens; i++) {
				ClangToken token = clangLine.getToken(i);
				if (token instanceof ClangFuncNameToken) {
					return clangLine;
				}
			}
		}
		return null;
	}

	/**
	 * Gets the indicated line number from the list after adjusting the line number when
	 * it falls outside the lower or upper limits of the array list. If there are no items
	 * in the array list then null is returned.
	 * @param lines the ordered array list of ClangLines.
	 * @param lineNumber the decompiler line number (1 based, not 0 based).
	 * @return the ClangLine for the indicated line number. Otherwise, null.
	 */
	private ClangLine getClangLine(List<ClangLine> lines, int lineNumber) {
		if (lines.isEmpty()) {
			return null;
		}
		int size = lines.size();
		if (lineNumber < 1) {
			lineNumber = 1;
		}
		if (lineNumber > size) {
			lineNumber = size;
		}
		return lines.get(lineNumber - 1);
	}

	private void setLockedLineNumbers(int leftLineNumber, int rightLineNumber) {
		lockedLeftLineNumber = leftLineNumber;
		lockedRightLineNumber = rightLineNumber;
	}

	private boolean searchRightForPair(int rightLineNumber) {
		if (setLeftFromRight(rightLineNumber)) {
			return true;
		}
		int lastLine = rightLines.size();
		int previous = rightLineNumber - 1;
		int next = rightLineNumber + 1;
		while (previous > 0 || next <= lastLine) {
			if (previous > 0) {
				if (setLeftFromRight(previous)) {
					return true;
				}
				previous--;
			}
			if (next <= lastLine) {
				if (setLeftFromRight(next)) {
					return true;
				}
				next++;
			}
		}
		return false;
	}

	private boolean setLeftFromRight(int rightLineNumber) {
		Integer leftLineNumber = leftToRightLineNumberPairing.getKey(rightLineNumber);
		if (leftLineNumber == null) {
			return false;
		}
		setLockedLineNumbers(leftLineNumber, rightLineNumber);
		return true;
	}

	private boolean searchLeftForPair(int leftLineNumber) {
		if (setRightFromLeft(leftLineNumber)) {
			return true;
		}
		int lastLine = leftLines.size();
		int previous = leftLineNumber - 1;
		int next = leftLineNumber + 1;
		while (previous > 0 || next <= lastLine) {
			if (previous > 0) {
				if (setRightFromLeft(previous)) {
					return true;
				}
				previous--;
			}
			if (next <= lastLine) {
				if (setRightFromLeft(next)) {
					return true;
				}
				next++;
			}
		}
		return false;
	}

	private boolean setRightFromLeft(int leftLineNumber) {
		Integer rightLineNumber = leftToRightLineNumberPairing.get(leftLineNumber);
		if (rightLineNumber == null) {
			return false;
		}
		setLockedLineNumbers(leftLineNumber, rightLineNumber);
		return true;

	}

}
