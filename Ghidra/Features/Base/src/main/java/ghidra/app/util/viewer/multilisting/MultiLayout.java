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
package ghidra.app.util.viewer.multilisting;

import ghidra.app.util.viewer.field.DummyFieldFactory;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.util.viewer.proxy.EmptyProxy;
import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.MultiRowLayout;
import docking.widgets.fieldpanel.support.RowLayout;

class MultiLayout {
	private Layout[] layouts;

	public MultiLayout() {
	}

	/**
	 * @param index2
	 * @param layouts
	 */
	public MultiLayout(Layout[] layouts, FormatManager formatMgr, DummyFieldFactory factory) {
		this.layouts = layouts;
		int[] rowHeights = new int[formatMgr.getMaxNumRows()];
		int id = getDefaultID(layouts);
		for (int i = 0; i < layouts.length; i++) {
			MultiRowLayout layout = (MultiRowLayout) layouts[i];
			if (layout == null) {
				layout =
					new MultiRowLayout(new RowLayout(new Field[] { factory.getField(
						EmptyProxy.EMPTY_PROXY, 0) }, id), 1);
				layouts[i] = layout;
			}
			layout.fillHeights(rowHeights);

		}
		for (int i = 0; i < layouts.length; i++) {
			MultiRowLayout layout = (MultiRowLayout) layouts[i];
			layout.align(rowHeights);
		}
	}

	private int getDefaultID(Layout[] layouts1) {
		for (Layout layout : layouts1) {
			if (layout != null) {
				MultiRowLayout multiRowLayout = (MultiRowLayout) layout;
				return multiRowLayout.getFirstRowID();
			}
		}
		return 0;
	}

	public boolean isEmpty() {
		return layouts == null;
	}

	/**
	 * @param modelID
	 * @return
	 */
	public Layout getLayout(int modelID) {
		return layouts[modelID];
	}

}
