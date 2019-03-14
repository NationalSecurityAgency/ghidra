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

import javax.swing.*;
import javax.swing.table.TableModel;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.app.plugin.core.instructionsearch.model.InstructionTableDataObject;
import ghidra.util.table.GhidraTableCellRenderer;

/**
 * Table cell renderer that allows us to keep the default behavior of the GTable renderer,
 * while adding some custom logic for changing background/foreground attributes.
 */
public class InstructionTableCellRenderer extends GhidraTableCellRenderer {

	/**
	 * 
	 * @param font
	 */
	public InstructionTableCellRenderer(Font font) {
		super(font);
	}

	/**
	 * Standard method that must be overridden when creating custom renderers.  The primary
	 * changes here are to change the attributes of the cell based on the contents of the
	 * underlying {@link InstructionTableDataObject}.
	 */
	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		Object value = data.getValue();
		JTable table = data.getTable();
		int column = data.getColumnViewIndex();

		boolean isSelected = data.isSelected();
		boolean hasFocus = data.hasFocus();

		// Do a null check on the input here to protect ourselves.  This value can be null 
		// in certain cases (eg: change resolution on the screen  [ctrl-+ on mac], then move the
		// instruction window to a different monitor, then click on a cell).
		if (value == null) {
			return this;
		}

		// Get the data object backing the cell.
		InstructionTableDataObject dataObject = (InstructionTableDataObject) value;
		String strData = dataObject.getData();

		GTableCellRenderingData renderData = data.copyWithNewValue(strData);

		JLabel theRenderer = (JLabel) super.getTableCellRendererComponent(renderData);

		setTextAttributes(table, value, column);
		setBackgroundAttributes(isSelected, hasFocus, dataObject);
		setBorderAttributes(dataObject, theRenderer);
		setForegroundAttributes(dataObject, theRenderer);

		return this;
	}

	/*********************************************************************************************
	 * PRIVATE METHODS
	 ********************************************************************************************/

	/**
	 * 
	 * @param dataObject
	 * @param theRenderer
	 */
	private void setBorderAttributes(InstructionTableDataObject dataObject, JLabel theRenderer) {
		theRenderer.setBorder(dataObject.getBorder());
	}

	/**
	 * 
	 * @param dataObject
	 * @param theRenderer
	 */
	private void setForegroundAttributes(InstructionTableDataObject dataObject,
			JLabel theRenderer) {
		// Change the foreground to use a font of our choosing.  The main reason is that we 
		// want to use a monospaced font for binary rendering.
		theRenderer.setForeground(dataObject.getForegroundColor());
		Font newFont = theRenderer.getFont().deriveFont(dataObject.getFontStyle());
		theRenderer.setFont(newFont);
	}

	/**
	 * 
	 * @param isSelected
	 * @param hasFocus
	 * @param dataObject
	 */
	private void setBackgroundAttributes(boolean isSelected, boolean hasFocus,
			InstructionTableDataObject dataObject) {
		// Set the background color based on what the cell says.  If it's selected, make it a 
		// bit darker.
		Color backgroundColor = dataObject.getBackgroundColor();
		if (backgroundColor != null) {
			if (isSelected || hasFocus) {
				setBackground(backgroundColor.darker());
			}
			else {
				setBackground(backgroundColor);
			}
		}
	}

	/**
	 * 
	 * @param table
	 * @param value
	 * @param col
	 */
	private void setTextAttributes(JTable table, Object value, int col) {
		setHorizontalAlignment(SwingConstants.LEFT);
		TableModel model = table.getModel();
		configureFont(table, model, col);
		setOpaque(true);
	}
}
