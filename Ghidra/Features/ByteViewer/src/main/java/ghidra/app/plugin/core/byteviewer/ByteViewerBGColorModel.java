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
package ghidra.app.plugin.core.byteviewer;

import java.awt.Color;
import java.math.BigInteger;

import docking.widgets.fieldpanel.support.BackgroundColorModel;
import docking.widgets.fieldpanel.support.FieldLocation;

/**
 * {@link BackgroundColorModel} that changes the color for the currently focused byte viewer row
 */
public class ByteViewerBGColorModel implements BackgroundColorModel {
	private Color bgColor = ByteViewerComponentProvider.BG_COLOR;
	private ByteViewerPanel panel;

	/**
	 * Creates a new model.
	 * 
	 * @param panel the byte viewer used to synchronize the current line across components
	 */
	public ByteViewerBGColorModel(ByteViewerPanel panel) {
		this.panel = panel;
	}

	@Override
	public Color getBackgroundColor(BigInteger index) {

		if (!panel.isHighlightCurrentLine()) {
			return bgColor;
		}

		ByteViewerComponent c = panel.getCurrentComponent();
		FieldLocation loc = c.getCursorLocation();
		BigInteger cursorIndex = loc.getIndex();
		if (index.equals(cursorIndex)) {
			return ByteViewerComponentProvider.CURRENT_LINE_COLOR;
		}
		return bgColor;
	}

	@Override
	public Color getDefaultBackgroundColor() {
		return bgColor;
	}

	@Override
	public void setDefaultBackgroundColor(Color c) {
		bgColor = c;
	}

}
