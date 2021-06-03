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
package ghidra.framework.plugintool.dialog;

import java.awt.Color;
import java.awt.Point;

import javax.swing.text.SimpleAttributeSet;

import docking.widgets.table.threaded.ThreadedTableModelListener;

/**
 * Panel that shows information about the selected extension in the {@link ExtensionTablePanel}. This
 * is essentially a view into the {@link ExtensionDetails} for the extension.
 * <p>
 * Note: The text is rendered as html to allow proper formatting (colors/font weight).
 */
class ExtensionDetailsPanel extends AbstractDetailsPanel {

	/** Attribute sets define the visual characteristics for each field */
	private SimpleAttributeSet nameAttrSet;
	private SimpleAttributeSet descrAttrSet;
	private SimpleAttributeSet authorAttrSet;
	private SimpleAttributeSet createdOnAttrSet;
	private SimpleAttributeSet versionAttrSet;
	private SimpleAttributeSet pathAttrSet;

	ExtensionDetailsPanel(ExtensionTablePanel tablePanel) {
		super();
		createFieldAttributes();
		createMainPanel();

		// Any time the table is reloaded or a new selection is made, we want to reload this 
		// panel. This ensures we are always viewing data for the currently-selected item.
		tablePanel.getTableModel().addThreadedTableModelListener(new ThreadedTableModelListener() {

			@Override
			public void loadPending() {
				// do nothing
			}

			@Override
			public void loadingStarted() {
				// do nothing
			}

			@Override
			public void loadingFinished(boolean wasCancelled) {
				setDescription(tablePanel.getSelectedItem());
			}
		});

		tablePanel.getTable().getSelectionModel().addListSelectionListener(e -> {
			setDescription(tablePanel.getSelectedItem());
		});
	}

	/**
	 * Updates this panel with the given extension.
	 * 
	 * @param details the extension to display
	 */
	public void setDescription(ExtensionDetails details) {

		clear();
		if (details == null) {
			return;
		}

		StringBuilder buffer = new StringBuilder("<HTML>");
		buffer.append("<TABLE cellpadding=2>");

		insertRowTitle(buffer, "Name");
		insertRowValue(buffer, details.getName(), nameAttrSet);

		insertRowTitle(buffer, "Description");
		insertRowValue(buffer, details.getDescription(), descrAttrSet);

		insertRowTitle(buffer, "Author");
		insertRowValue(buffer, details.getAuthor(), authorAttrSet);

		insertRowTitle(buffer, "Created-on");
		String date = details.getCreatedOn();
		insertRowValue(buffer, date, createdOnAttrSet);

		insertRowTitle(buffer, "Version");

		String version = details.getVersion();
		if (version.equals("@extversion@")) {
			insertRowValue(buffer, "", versionAttrSet);
		}
		else {
			insertRowValue(buffer, version, versionAttrSet);
		}

		String installPath = details.getInstallPath();
		if (installPath != null) {
			insertRowTitle(buffer, "Install Path");
			insertRowValue(buffer, installPath, pathAttrSet);
		}

		buffer.append("</TABLE>");

		textLabel.setText(buffer.toString());
		sp.getViewport().setViewPosition(new Point(0, 0));
	}

	@Override
	protected void createFieldAttributes() {
		titleAttrSet = createAttributeSet(new Color(140, 0, 0));
		nameAttrSet = createAttributeSet(new Color(0, 204, 51));
		descrAttrSet = createAttributeSet(Color.BLUE);
		authorAttrSet = createAttributeSet(Color.BLUE);
		createdOnAttrSet = createAttributeSet(Color.BLUE);
		versionAttrSet = createAttributeSet(Color.BLUE);
		pathAttrSet = createAttributeSet(Color.BLUE);
	}
}
