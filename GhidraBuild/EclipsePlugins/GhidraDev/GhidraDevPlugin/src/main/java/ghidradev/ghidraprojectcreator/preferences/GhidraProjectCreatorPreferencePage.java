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
package ghidradev.ghidraprojectcreator.preferences;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Collectors;

import org.eclipse.jface.preference.IPreferenceStore;
import org.eclipse.jface.preference.PreferencePage;
import org.eclipse.swt.SWT;
import org.eclipse.swt.graphics.Font;
import org.eclipse.swt.graphics.FontData;
import org.eclipse.swt.layout.*;
import org.eclipse.swt.widgets.*;
import org.eclipse.ui.IWorkbench;
import org.eclipse.ui.IWorkbenchPreferencePage;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.ApplicationProperties;
import ghidra.framework.ApplicationVersion;
import ghidradev.Activator;
import ghidradev.EclipseMessageUtils;
import utility.application.ApplicationLayout;

/**
 * Page for Ghidra project creator preferences.
 */
public class GhidraProjectCreatorPreferencePage extends PreferencePage
implements IWorkbenchPreferencePage {

	private static ApplicationVersion MIN_GHIDRA_VERSION = new ApplicationVersion("9.1");

	private Table table;
	private Button addButton;
	private Button removeButton;

	public GhidraProjectCreatorPreferencePage() {
		super();
	}

	@Override
	public void init(IWorkbench workbench) {
		// Nothing to do
	}

	@Override
	protected IPreferenceStore doGetPreferenceStore() {
		return Activator.getDefault().getPreferenceStore();
	}

	@Override
	protected Control createContents(Composite parent) {
		noDefaultButton();
		
		FontData fontData = parent.getFont().getFontData()[0];
		Font bold =	new Font(parent.getDisplay(), fontData.getName(), fontData.getHeight(), SWT.BOLD);

		Composite container = new Composite(parent, SWT.None);
		container.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true));
		container.setLayout(new GridLayout(2, false));

		// Description label
		Label descriptionLabel = new Label(container, SWT.NULL);
		descriptionLabel.setText("Add or remove Ghidra installation directories.\n" +
			"The checked Ghidra installation is the default used when creating new projects.\n" +
			"Red entries correspond to invalid Ghidra installation directories.");
		new Label(container, SWT.NONE).setText(""); // filler

		// Ghidra installations table
		table = new Table(container, SWT.CHECK | SWT.BORDER | SWT.FULL_SELECTION);
		table.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true));
		table.setHeaderVisible(true);
		table.setLinesVisible(true);
		table.addListener(SWT.Selection, evt -> {
			if (evt.detail == SWT.CHECK) {
				for (TableItem item : table.getItems()) {
					item.setChecked(item.equals(evt.item));
					item.setFont(item.equals(evt.item) ? bold : parent.getFont());
				}
			}
		});
		TableColumn col = new TableColumn(table, SWT.FILL);
		col.setText("Ghidra installation directories");
		col.setWidth(400);
		for (File dir : GhidraProjectCreatorPreferences.getGhidraInstallDirs()) {
			TableItem item = new TableItem(table, SWT.NONE);
			item.setText(dir.getAbsolutePath());
			try {
				validateGhidraInstallation(dir);
				item.setForeground(parent.getDisplay().getSystemColor(SWT.COLOR_BLACK));
			}
			catch (IOException e) {
				item.setForeground(parent.getDisplay().getSystemColor(SWT.COLOR_RED));
			}
			if (dir.equals(GhidraProjectCreatorPreferences.getGhidraDefaultInstallDir())) {
				item.setFont(bold);
				item.setChecked(true);
			}
		}
		if (table.getItemCount() > 0) {
			col.pack();
		}

		// Buttons
		Composite buttons = new Composite(container, SWT.None);
		buttons.setLayoutData(new GridData(GridData.VERTICAL_ALIGN_BEGINNING));
		buttons.setLayout(new FillLayout(SWT.VERTICAL));

		// Add button
		addButton = new Button(buttons, SWT.PUSH);
		addButton.setText("Add...");
		addButton.addListener(SWT.Selection, evt -> {
			DirectoryDialog dialog = new DirectoryDialog(container.getShell());
			String path = dialog.open();
			if (path == null) {
				return;
			}
			if (Arrays.stream(table.getItems()).anyMatch(item -> item.getText().equals(path))) {
				EclipseMessageUtils.showErrorDialog("Ghidra installation already specified.");
				return;
			}
			try {
				validateGhidraInstallation(new File(path));
				TableItem item = new TableItem(table, SWT.NONE);
				item.setText(path);
				item.setChecked(table.getItemCount() == 1);
				item.setFont(item.getChecked() ? bold : parent.getFont());
			}
			catch (IOException e) {
				EclipseMessageUtils.showErrorDialog(e.getMessage());
			}
		});

		// Remove button
		removeButton = new Button(buttons, SWT.PUSH);
		removeButton.setText("Remove");
		removeButton.addListener(SWT.Selection, evt -> {
			int selectionIndex = table.getSelectionIndex();
			if (selectionIndex == -1) {
				return;
			}
			boolean wasDefault = table.getItem(selectionIndex).getChecked();
			table.remove(selectionIndex);
			if (table.getItemCount() > 0) {
				if (selectionIndex < table.getItemCount()) {
					table.select(selectionIndex);
				}
				else {
					table.select(selectionIndex - 1);
				}
				if (wasDefault) {
					TableItem item = table.getItem(table.getSelectionIndex());
					item.setChecked(true);
					item.setFont(bold);
				}
			}
		});

		return parent;
	}

	@Override
	public boolean performOk() {
		super.performOk();

		//@formatter:off
		GhidraProjectCreatorPreferences.setGhidraInstallDirs(
			Arrays.stream(table.getItems())
			.map(item -> new File(item.getText()))
			.collect(Collectors.toSet())
		);

		GhidraProjectCreatorPreferences.setDefaultGhidraInstallDir(
			Arrays.stream(table.getItems())
			.filter(TableItem::getChecked)
			.findFirst()
			.map(item -> new File(item.getText()))
			.orElse(null)
		);
		//@formatter:on

		return true;
	}

	/**
	 * Validates the given Ghidra installation directory.
	 * 
	 * @param ghidraInstallDir The Ghidra installation directory to validate.
	 * @throws IOException If the given Ghidra installation directory is not valid.  The exception's
	 *   message has more detailed information on why it was not valid.
	 */
	public static void validateGhidraInstallation(File ghidraInstallDir) throws IOException {
		ApplicationLayout layout;
		try {
			layout = new GhidraApplicationLayout(ghidraInstallDir);
		}
		catch (IOException e) {
			throw new IOException("Not a valid Ghidra installation.");			
		}
		ApplicationProperties applicationProperties = layout.getApplicationProperties();
		ApplicationVersion version;
		try {
			version = new ApplicationVersion(applicationProperties.getApplicationVersion());
		}
		catch (IllegalArgumentException e) {
			throw new IOException("Error parsing application version. " + e.getMessage() + ".");
		}
		if (version.compareTo(MIN_GHIDRA_VERSION) < 0) {
			throw new IOException(
				"Ghidra installation must be version " + MIN_GHIDRA_VERSION + " or later.");
		}
		String layoutVersion = applicationProperties.getProperty(
			ApplicationProperties.APPLICATION_LAYOUT_VERSION_PROPERTY);
		if (layoutVersion == null || !layoutVersion.equals("1")) {
			// We can be smarter about this check and what we support later, once the layout version 
			// actually changes.
			throw new IOException(
				"Ghidra application layout is not supported.  Please upgrade " +
					Activator.PLUGIN_ID + " to use this version of Ghidra.");
		}
	}
}
