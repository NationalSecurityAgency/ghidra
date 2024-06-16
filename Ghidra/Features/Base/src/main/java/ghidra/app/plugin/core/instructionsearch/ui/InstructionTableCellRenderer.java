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
package ghidra.app.plugin.core.instructionsearch.ui;

import java.awt.*;

import javax.swing.JLabel;
import javax.swing.SwingConstants;

import docking.widgets.table.GTableCellRenderingData;
import generic.theme.Gui;
import ghidra.app.plugin.core.instructionsearch.model.InstructionTableDataObject;
import ghidra.util.table.GhidraTableCellRenderer;

/**
 * Table cell renderer that allows us to keep the default behavior of the GTable renderer,
 * while adding some custom logic for changing background/foreground attributes.
 */
public class InstructionTableCellRenderer extends GhidraTableCellRenderer {
	private static final String FONT_ID = "font.plugin.instruction.table.renderer";

	public InstructionTableCellRenderer() {
		super(Gui.getFont(FONT_ID));
	}

	/**
	 * Standard method that must be overridden when creating custom renderers.  The primary
	 * changes here are to change the attributes of the cell based on the contents of the
	 * underlying {@link InstructionTableDataObject}.
	 */
	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		Object value = data.getValue();
		boolean isSelected = data.isSelected();
		boolean hasFocus = data.hasFocus();
		if (value == null) {
			return this;
		}

		InstructionTableDataObject dataObject = (InstructionTableDataObject) value;
		String strData = dataObject.getData();

		GTableCellRenderingData renderData = data.copyWithNewValue(strData);

		JLabel theRenderer = (JLabel) super.getTableCellRendererComponent(renderData);

		setTextAttributes();
		setBackgroundAttributes(isSelected, hasFocus, dataObject);
		setBorderAttributes(dataObject, theRenderer);
		setForegroundAttributes(dataObject, theRenderer);

		return this;
	}

	private void setBorderAttributes(InstructionTableDataObject dataObject, JLabel theRenderer) {
		theRenderer.setBorder(dataObject.getBorder());
	}

	private void setForegroundAttributes(InstructionTableDataObject dataObject,
			JLabel theRenderer) {
		theRenderer.setForeground(dataObject.getForegroundColor());
		Font newFont = theRenderer.getFont().deriveFont(dataObject.getFontStyle());
		theRenderer.setFont(newFont);
	}

	private void setBackgroundAttributes(boolean isSelected, boolean hasFocus,
			InstructionTableDataObject dataObject) {
		Color backgroundColor = dataObject.getBackgroundColor();
		if (backgroundColor != null) {
			if (isSelected || hasFocus) {
				setBackground(Gui.darker(backgroundColor));
			}
			else {
				setBackground(backgroundColor);
			}
		}
	}

	private void setTextAttributes() {
		setHorizontalAlignment(SwingConstants.LEFT);
		setFont(getDefaultFont());
		setOpaque(true);
	}
}
