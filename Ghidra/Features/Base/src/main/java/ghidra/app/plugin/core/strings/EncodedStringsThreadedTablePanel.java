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
package ghidra.app.plugin.core.strings;

import java.awt.BorderLayout;
import java.awt.Component;

import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.util.table.GhidraThreadedTablePanel;

/**
 * A Ghidra table panel that can show a custom overlay instead of an empty table.
 * 
 * @param <T> table row type
 */
class EncodedStringsThreadedTablePanel<T> extends GhidraThreadedTablePanel<T> {

	Component emptyTableOverlayComponent;
	Component previousCenterComponent;

	public EncodedStringsThreadedTablePanel(ThreadedTableModel<T, ?> model, int minUpdateDelay,
			Component emptyTableOverlayComponent) {
		super(model, minUpdateDelay);
		this.emptyTableOverlayComponent = emptyTableOverlayComponent;
	}

	public void showEmptyTableOverlay(boolean b) {
		BorderLayout layout = (BorderLayout) getLayout();
		if (previousCenterComponent == null) {
			previousCenterComponent = layout.getLayoutComponent(BorderLayout.CENTER);
		}
		Component currentCenterComponent = layout.getLayoutComponent(BorderLayout.CENTER);

		if (b) {
			if (currentCenterComponent != emptyTableOverlayComponent) {
				remove(previousCenterComponent);
				add(emptyTableOverlayComponent, BorderLayout.CENTER);
			}
		}
		else {
			if (currentCenterComponent != previousCenterComponent) {
				remove(emptyTableOverlayComponent);
				add(previousCenterComponent, BorderLayout.CENTER);
			}
		}

		invalidate();
		repaint();
	}

}
