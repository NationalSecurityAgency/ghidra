/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import java.awt.Color;

import docking.widgets.fieldpanel.support.FieldLocation;

public class LayoutBackgroundColorManagerAdapter implements LayoutBackgroundColorManager {

	private final LayoutBackgroundColorManager layoutSelectionMap;
	private int start;
	private int end;
	private boolean isLastRow;

	public LayoutBackgroundColorManagerAdapter(LayoutBackgroundColorManager layoutColorMap) {
		this.layoutSelectionMap = layoutColorMap;
	}
	public Color getBackgroundColor() {
		return layoutSelectionMap.getBackgroundColor();
	}

	public FieldBackgroundColorManager getFieldBackgroundColorManager(int fieldNum) {
		return layoutSelectionMap.getFieldBackgroundColorManager(fieldNum+start);
	}
	public void setRange(int start, int end, boolean isLastRow) {
		this.start = start;
		this.end = end;
		this.isLastRow = isLastRow;
	}
	public Color getPaddingColor(int gap) {
		if (gap == -1) {
			if (isLastRow) {
				return layoutSelectionMap.getPaddingColor(-1);
			}
			gap = end-start;
		}
		return layoutSelectionMap.getPaddingColor(gap+start);
	}
	public Color getBackgroundColor(FieldLocation location) {
		return layoutSelectionMap.getBackgroundColor(location);
	}
}
