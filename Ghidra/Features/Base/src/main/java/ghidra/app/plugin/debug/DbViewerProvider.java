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
package ghidra.app.plugin.debug;

import javax.swing.JComponent;

import db.DBHandle;
import docking.WindowPosition;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.Plugin;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

public class DbViewerProvider extends ComponentProviderAdapter {

	private static final String ICON_IMAGE = "images/zoom.png";

	private DBHandle dbh;
	private String dbName;
	private DbViewerComponent comp;

	public DbViewerProvider(Plugin plugin) {
		super(plugin.getTool(), "Database Viewer", plugin.getName());

		setIcon(ResourceManager.loadImage(ICON_IMAGE));
		setDefaultWindowPosition(WindowPosition.BOTTOM);

		setHelpLocation(new HelpLocation(plugin.getName(), "DbViewer"));
	}

	protected void closeDatabase() {
		if (comp != null) {
			comp.closeDatabase();
		}
		dbh = null;
	}

	/**
	 * Opens the database for viewing its table data.
	 * @param databaseName the name of the database.
	 * @param handle the DBHandle for the open database
	 */
	protected void openDatabase(String databaseName, DBHandle handle) {
		if (comp != null) {
			comp.openDatabase(databaseName, handle);
		}
		this.dbh = handle;
		this.dbName = databaseName;
	}

	void refresh() {
		if (comp != null) {
			comp.refresh();
		}
	}

	void dispose() {
		if (comp != null) {
			comp.dispose();
			comp = null;
		}
	}

	@Override
	public JComponent getComponent() {
		if (comp == null) {
			comp = new DbViewerComponent();
			if (dbh != null) {
				comp.openDatabase(dbName, dbh);
			}
		}
		return comp;
	}
}
