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
package docking.widgets.table;

import java.awt.Component;

import javax.swing.JComponent;
import javax.swing.table.TableCellRenderer;

import docking.widgets.GComponent;

public class DefaultTableCellRendererWrapper extends GTableCellRenderer {

	private final TableCellRenderer renderer;

	public DefaultTableCellRendererWrapper(TableCellRenderer renderer) {
		this.renderer = renderer;

		// we have to do this again here, as the super constructor called us back before we
		// set the 'renderer' variable
		setHTMLRenderingEnabled(false);
	}

	/**
	 * Enables and disables the rendering of HTML content in this renderer.  If enabled, this
	 * renderer will interpret HTML content when the text this renderer is showing begins with 
	 * {@code <html>}
	 * 
	 * @param enable true to enable HTML rendering; false to disable it
	 */
	@Override
	public void setHTMLRenderingEnabled(boolean enable) {
		if (renderer instanceof JComponent) {
			((JComponent) renderer).putClientProperty(GComponent.HTML_DISABLE_STRING, !enable);
		}
		super.setHTMLRenderingEnabled(enable);
	}

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		Component rendererComponent = renderer.getTableCellRendererComponent(data.getTable(),
			data.getValue(), data.isSelected(), data.hasFocus(), data.getRowViewIndex(),
			data.getColumnViewIndex());

		JComponent thisRenderer = (JComponent) super.getTableCellRendererComponent(data);

		rendererComponent.setBackground(thisRenderer.getBackground());

		if (rendererComponent instanceof JComponent) {
			((JComponent) rendererComponent).setBorder(thisRenderer.getBorder());
		}

		return rendererComponent;
	}
}
