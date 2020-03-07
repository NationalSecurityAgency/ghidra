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
package docking.widgets.fieldpanel.internal;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import docking.widgets.fieldpanel.FieldPanel;
import ghidra.util.exception.AssertException;

/**
 * A LineLockedFieldPanelCoordinator coordinates the scrolling of a set of field panels by sharing 
 * bound scroll models that are locked together by a set of line numbers.
 * All the field panels are locked together at the line numbers specified in the locked line array.
 * In other words this coordinator tries to keep the indicated line for each field panel
 * side by side with the indicated line for each other field panel.
 */
public class LineLockedFieldPanelCoordinator extends FieldPanelCoordinator {

	// Keep an array of the line number for each field panel where we are locking
	// these field panels together when scrolling or moving the cursor location.
	protected BigInteger[] lockedLineNumbers;

	public LineLockedFieldPanelCoordinator(FieldPanel[] panels) {
		super(panels);
		resetLockedLines();
	}

	/**
	 * Resets the locked line numbers for this field panel coordinator to their default
	 * of each being zero.
	 */
	public void resetLockedLines() {
		// Make the locked line numbers default to 0.
		lockedLineNumbers = new BigInteger[panels.length];
		for (int i = 0; i < lockedLineNumbers.length; i++) {
			this.lockedLineNumbers[i] = BigInteger.ZERO;
		}
	}

	/**
	 * Call this method whenever you want to change the line numbers that are locked together 
	 * for the associated field panels.
	 * @param lockedLineNumbers the array of locked line numbers that are directly associated with
	 * the array of field panels.<BR>
	 * Important: Make sure the line numbers are in the order that matches the field panels in the array.
	 */
	public void setLockedLines(BigInteger[] lockedLineNumbers) {
		if (lockedLineNumbers.length != this.lockedLineNumbers.length) {
			throw new AssertException("The number of lines(" + lockedLineNumbers.length +
				") must exactly match the number of panels(" + this.lockedLineNumbers.length +
				").");
		}
		for (int i = 0; i < lockedLineNumbers.length; i++) {
			if (lockedLineNumbers[i] == null) {
				lockedLineNumbers[i] = BigInteger.ZERO;
			}
		}
		for (int i = 0; i < lockedLineNumbers.length; i++) {
			if (!this.lockedLineNumbers[i].equals(lockedLineNumbers[i])) {
				this.lockedLineNumbers[i] = lockedLineNumbers[i];
			}
		}
	}

	/**
	 * Adds the given field panel to the list of panels to coordinate.
	 * @param fp the field panel to add.
	 */
	@Override
	public void add(FieldPanel fp) {
		// Adjust our locked line number array.
		BigInteger[] newLineNumbers = new BigInteger[lockedLineNumbers.length + 1];
		System.arraycopy(lockedLineNumbers, 0, newLineNumbers, 0, lockedLineNumbers.length);
		newLineNumbers[panels.length] = BigInteger.valueOf(0L);
		lockedLineNumbers = newLineNumbers;

		// The super class will adjust the field panel array.
		super.add(fp);
	}

	/**
	 * Removes the given field panel from the list of those to be coordinated.
	 */
	@Override
	public void remove(FieldPanel fp) {
		List<BigInteger> lineNumberList = new ArrayList<>(panels.length);
		// Adjust our locked line number array.
		int length = panels.length;
		for (int i = 0; i < length; i++) {
			if (panels[i] != fp) {
				lineNumberList.add(lockedLineNumbers[i]);
			}
		}
		lockedLineNumbers = lineNumberList.toArray(new BigInteger[lineNumberList.size()]);

		// The super class will adjust the field panel array.
		super.remove(fp);
	}

	@Override
	public void viewChanged(FieldPanel fp, BigInteger index, int xPos, int yPos) {
		if (valuesChanging)
			return;
		try {
			valuesChanging = true;
			BigInteger fpLineNumber = getLockedLineForPanel(fp);
			if (fpLineNumber == null) {
				throw new AssertException("Couldn't find line number for indicated field panel.");
			}
			// Position the views for the other panels to match the changed one the best they can.
			for (int i = 0; i < panels.length; i++) {
				if (panels[i] != fp) {
					BigInteger adjustment = lockedLineNumbers[i].subtract(fpLineNumber);
					BigInteger panelIndex = index.add(adjustment);
					if (panelIndex.longValue() < 0) {
						panelIndex = BigInteger.valueOf(0L);
					}
					panels[i].setViewerPosition(panelIndex, xPos, yPos);
				}
			}
		}
		finally {
			valuesChanging = false;
		}
	}

	/**
	 * Gets the locked line value for the indicated panel.
	 * @param fp the field panel whose locked line value is wanted.
	 * @return the locked line value or null if the panel isn't found.
	 */
	protected BigInteger getLockedLineForPanel(FieldPanel fp) {
		for (int i = 0; i < lockedLineNumbers.length; i++) {
			if (panels[i] == fp) {
				return lockedLineNumbers[i];
			}
		}
		return null;
	}
}
