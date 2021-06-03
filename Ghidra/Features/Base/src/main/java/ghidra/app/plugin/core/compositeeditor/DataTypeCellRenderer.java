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
package ghidra.app.plugin.core.compositeeditor;

import java.awt.Color;
import java.awt.Component;

import javax.swing.JLabel;

import docking.widgets.table.GTableCellRenderer;
import docking.widgets.table.GTableCellRenderingData;
import ghidra.app.util.ToolTipUtils;
import ghidra.program.model.data.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.SystemUtilities;

public class DataTypeCellRenderer extends GTableCellRenderer {
	private static final long serialVersionUID = 1L;

	private DataTypeManager originalDTM;

	public DataTypeCellRenderer(DataTypeManager originalDataTypeManager) {
		this.originalDTM = originalDataTypeManager;
	}

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		Object value = data.getValue();

		String dtString = "";
		String tooltipText = null;
		boolean useRed = false;
		DataType dt = null;

		if (value instanceof DataTypeInstance) {
			dt = ((DataTypeInstance) value).getDataType();
			tooltipText = getDataTypeToolTip(dt);
			dtString = dt.getDisplayName();
			if (dt.isNotYetDefined()) {
				useRed = true;
			}
		}

		GTableCellRenderingData renderData = data.copyWithNewValue(dtString);

		JLabel c = (JLabel) super.getTableCellRendererComponent(renderData);

		c.setToolTipText(tooltipText);

		if (useRed) {
			c.setForeground(Color.RED);
		}

		return c;
	}

	private String getDataTypeToolTip(DataType dataType) {

		DataTypeManager dataTypeManager = dataType.getDataTypeManager();
		// This checks for null dataTypeManager below since BadDataType won't have one.
		SourceArchive sourceArchive = dataType.getSourceArchive();

		boolean localSource = (sourceArchive == null) ||
			((dataTypeManager != null) && SystemUtilities.isEqual(dataTypeManager.getUniversalID(),
				sourceArchive.getSourceArchiveID()));
		if (localSource) {
			sourceArchive = originalDTM.getSourceArchive(originalDTM.getUniversalID());
		}

		DataType foundDataType = originalDTM.getDataType(dataType.getDataTypePath());

		String displayName = "";
		if (foundDataType != null && (dataTypeManager != null)) {
			displayName = dataTypeManager.getName();
		}
		displayName += dataType.getPathName();
		if (!localSource) {
			displayName += "  (" + sourceArchive.getName() + ")";
		}
		displayName = HTMLUtilities.friendlyEncodeHTML(displayName);

		String toolTipText = ToolTipUtils.getToolTipText(dataType);
		String headerText = "<HTML><b>" + displayName + "</b><BR>";
		toolTipText = toolTipText.replace("<HTML>", headerText);
		return toolTipText;
	}
}
