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

import ghidra.util.exception.AssertException;

import java.math.BigInteger;

import docking.widgets.fieldpanel.*;

/**
 * A LayoutLockedFieldPanelCoordinator is an extension of a LineLockedFieldPanelCoordinator that
 * handles the fact that field panel layouts vary in size. It coordinates the scrolling of a set 
 * of field panels by sharing bound scroll models that are locked together by a set of index 
 * numbers for the FieldPanel Layouts. All the field panels are locked together at the index 
 * numbers specified in the locked line array.
 * In other words this coordinator tries to keep the layout indicated by the line (or index)
 * for each field panel side by side with the indicated layout for each other field panel.
 * <br>Note: The layouts that are locked together will be positioned so that the bottom of those
 * layouts line up within the field panels.
 */
public class LayoutLockedFieldPanelCoordinator extends LineLockedFieldPanelCoordinator {

	/**
	 * Constructor for the coordinator.
	 * @param panels the field panels that will have their positions coordinated with each other.
	 */
	public LayoutLockedFieldPanelCoordinator(FieldPanel[] panels) {
		super(panels);
	}

	@Override
	public void viewChanged(FieldPanel fp, BigInteger index, int xPos, int yPos) {
		if (valuesChanging)
			return;
		try {
			valuesChanging = true;
			// "lockedLineIndex" is the IndexMap index indicating where this field panel 
			// is locked to the other when scrolling.
			BigInteger lockedLineIndex1 = getLockedLineForPanel(fp);
			if (lockedLineIndex1 == null) { // This shouldn't happen.
				throw new AssertException("Couldn't find line number for indicated field panel."
					+ " FieldPanel is not one of those being managed by this coordinator.");
			}
			
			// "topIndex" is the IndexMap index of the top of the listing in view.
			BigInteger topIndex1 = index;
			LayoutModel layoutModel1 = fp.getLayoutModel();
			Layout lockedLineLayout1 = layoutModel1.getLayout(lockedLineIndex1);
			if (lockedLineLayout1 == null) {
				return; // transitioning from one function to another.
			}
			
			// "lockedLineHeight" is the height of the layout in this field panel 
			// where it is locked to the other panel when scrolling.
			int lockedLineHeight1 = lockedLineLayout1.getHeight();

			// numIndexes is the total number of indexes in this field panels indexMap.
			BigInteger numIndexes1 = layoutModel1.getNumIndexes();
			Layout firstLayout1 = layoutModel1.getLayout(topIndex1);
			
			// "yPos" is a negative number indicating the number of pixels the start of the current 
			// layout is above the top of the field panel view.
			
			// "remainingHeight" is the number of pixels vertically from the first visible pixel 
			// in the layout at the top of the listing view to the end of that layout.
			int remainingHeight = firstLayout1.getHeight() + yPos;

			// "offsetInLayout" is the number of pixels that the top of the listing view is below
			// the start of the current layout.
			int offsetInLayout1 = 0;
			int offsetFromLockedIndex1 = 0;
			if (lockedLineIndex1.compareTo(topIndex1) == 0) {
				offsetInLayout1 -= yPos;
				offsetFromLockedIndex1 += offsetInLayout1;
			}
			else if (lockedLineIndex1.compareTo(topIndex1) < 0) {
				BigInteger currentIndex1 = lockedLineIndex1;
				while (currentIndex1 != null && (currentIndex1.compareTo(numIndexes1) < 0) &&
					currentIndex1.compareTo(topIndex1) < 0) {
					Layout currentLayout = layoutModel1.getLayout(currentIndex1);
					if (currentLayout != null) {
						offsetFromLockedIndex1 += currentLayout.getHeight();
					}
					currentIndex1 = layoutModel1.getIndexAfter(currentIndex1);
				}
				offsetFromLockedIndex1 -= yPos;
			}
			else { // lockedlineIndex1 > topIndex1
				BigInteger currentIndex1 = layoutModel1.getIndexAfter(topIndex1);
				while (currentIndex1 != null && (currentIndex1.compareTo(numIndexes1) < 0) &&
					currentIndex1.compareTo(lockedLineIndex1) < 0) {
					Layout currentLayout = layoutModel1.getLayout(currentIndex1);
					if (currentLayout != null) {
						offsetFromLockedIndex1 -= currentLayout.getHeight();
					}
					currentIndex1 = layoutModel1.getIndexAfter(currentIndex1);
				}
				offsetFromLockedIndex1 -= remainingHeight;
			}

			// Position the views for the other panels to match the changed one the best they can.
			for (int i = 0; i < panels.length; i++) {
				if (panels[i] != fp) {
					// Get the difference in height between our two line locked layouts.
					LayoutModel layoutModel2 = panels[i].getLayoutModel();
					BigInteger numIndexes2 = layoutModel2.getNumIndexes();
					BigInteger lockedLineIndex2 = lockedLineNumbers[i];
					Layout lockedLineLayout2 = layoutModel2.getLayout(lockedLineIndex2);
					if (lockedLineLayout2 == null) {
						return; // Initializing panels.
					}
					int lockedLineHeight2 = lockedLineLayout2.getHeight();

					// Handle when the locked line's layout is at the top of the viewer.
					if (lockedLineIndex1.equals(topIndex1)) {
						int difference = lockedLineHeight1 - lockedLineHeight2; // positive means layout1 is larger.
						int yPos2 = yPos + difference;
						// A negative yPos indicates the number of pixels to move the layout
						// above the top of the view.
						panels[i].setViewerPosition(lockedLineIndex2, xPos, yPos2);
						return;
					}

					// Start with the layout of the line locked index and position the top of the 
					// view at the same distance from it as the other view is from the layout for
					// its locked line.
					int offsetFromLockedIndex2 =
						offsetFromLockedIndex1 + (lockedLineHeight2 - lockedLineHeight1);
					int remainingOffset2 = offsetFromLockedIndex2;
					BigInteger currentIndex2 = lockedLineIndex2;
					if (remainingOffset2 < 0) {
						currentIndex2 = layoutModel2.getIndexBefore(currentIndex2);
					}
					while (currentIndex2 != null && currentIndex2.compareTo(BigInteger.ZERO) >= 0 &&
						currentIndex2.compareTo(numIndexes2) < 0) {
						Layout currentLayout2 = layoutModel2.getLayout(currentIndex2);
						// Gaps in the code will cause the currentIndex to be the last byte's 
						// index before the gap. This results in a null layout for that index, 
						// so we need to go again to get past it.
						if (currentLayout2 == null) {
							if (remainingOffset2 < 0) {
								// Go again when processing layout heights in reverse direction.
								currentIndex2 = layoutModel2.getIndexBefore(currentIndex2);
								continue;
							}
							else if (remainingOffset2 > 0) {
								// Go again when processing layout heights in forward direction.
								currentIndex2 = layoutModel2.getIndexAfter(currentIndex2);
								continue;
							}
							return; // currentLayout2 is null.
						}
						int height = currentLayout2.getHeight();
						if (remainingOffset2 == 0) {
							panels[i].setViewerPosition(currentIndex2, xPos, 0);
							return;
						}
						else if (remainingOffset2 < 0) {
							int offset = height + remainingOffset2;
							if (offset >= 0) {
								panels[i].setViewerPosition(currentIndex2, xPos, -offset);
								return;
							}
							currentIndex2 = layoutModel2.getIndexBefore(currentIndex2);
							remainingOffset2 = offset;
						}
						else { // remainingOffset2 > 0
							if (remainingOffset2 < height) {
								panels[i].setViewerPosition(currentIndex2, xPos, -remainingOffset2);
								return;
							}
							currentIndex2 = layoutModel2.getIndexAfter(currentIndex2);
							remainingOffset2 -= height;
						}
					}
				}
			}
		}
		finally {
			valuesChanging = false;
		}
	}
}
