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
package ghidra.app.merge.structures;

import java.awt.event.AdjustmentEvent;
import java.util.ArrayList;
import java.util.List;

/**
 * Class for coordinating the scrolling and line selection of the three structure display. 
 */
class DisplayCoordinator {
	private List<CoordinatedStructureDisplay> displays = new ArrayList<>();
	private boolean isChanging;

	void registerDisplay(CoordinatedStructureDisplay display) {
		displays.add(display);
	}

	void notifySelectionChanged(CoordinatedStructureDisplay changedDisplay,
			int selectedIndex, ComparisonItem item) {
		if (isChanging) {
			return;
		}
		try {
			isChanging = true;
			for (CoordinatedStructureDisplay display : displays) {
				display.setSelectedItem(changedDisplay, selectedIndex, item);
			}
		}
		finally {
			isChanging = false;
		}

	}

	void notifyHorizontalScrollChanged(CoordinatedStructureDisplay d, AdjustmentEvent e) {
		if (isChanging) {
			return;
		}
		try {
			isChanging = true;
			for (CoordinatedStructureDisplay display : displays) {
				if (display != d) {
					display.setHorizontalScroll(d, e.getValue());
				}
			}
		}
		finally {
			isChanging = false;
		}
	}

	void notifyVerticalScrollChanged(CoordinatedStructureDisplay d, AdjustmentEvent e) {
		if (isChanging) {
			return;
		}
		try {
			isChanging = true;
			for (CoordinatedStructureDisplay display : displays) {
				if (display != d) {
					display.setVerticalScroll(d, e.getValue());
				}
			}
		}
		finally {
			isChanging = false;
		}
	}

	void setChanging(boolean b) {
		isChanging = b;
	}

}
