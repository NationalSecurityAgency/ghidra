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
package ghidra.app.util.viewer.multilisting;

import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.MultiRowLayout;
import docking.widgets.fieldpanel.support.MultiRowLayout.RowHeights;
import docking.widgets.fieldpanel.support.RowLayout;
import ghidra.app.util.viewer.field.DummyFieldFactory;
import ghidra.app.util.viewer.proxy.EmptyProxy;

class MultiLayout {
	private Layout[] layouts;

	public MultiLayout() {
	}

	public MultiLayout(Layout[] layouts, DummyFieldFactory factory) {
		this.layouts = layouts;

		RowHeights[] allHeights = new RowHeights[layouts.length];
		int id = getDefaultID(layouts);
		for (int i = 0; i < layouts.length; i++) {
			MultiRowLayout layout = (MultiRowLayout) layouts[i];
			if (layout == null) {
				Field[] fields = new Field[] { factory.getField(EmptyProxy.EMPTY_PROXY, 0) };
				layout = new MultiRowLayout(new RowLayout(fields, id), 1);
				layouts[i] = layout;
			}

			allHeights[i] = layout.getRowHeights();
		}

		int n = allHeights.length;
		RowHeights combinedRowHeights = new RowHeights();
		for (int i = 0; i < n; i++) {
			combinedRowHeights.merge(allHeights[i]);
		}

		for (Layout layout : layouts) {
			((MultiRowLayout) layout).align(combinedRowHeights);
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

	public Layout getLayout(int modelID) {
		return layouts[modelID];
	}
}
