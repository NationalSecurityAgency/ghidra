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
package ghidra.app.util.query;

import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.plugin.core.table.TableServicePlugin;
import ghidra.app.tablechooser.TableChooserDialog;
import ghidra.app.tablechooser.TableChooserExecutor;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.listing.Program;
import ghidra.util.table.GhidraProgramTableModel;

import java.awt.Color;

import javax.swing.ImageIcon;

/**
 * Service to show a component that has a JTable given a table model
 * that builds up its data dynamically (a <code>ThreadedTableModel</code>). 
 */
@ServiceInfo(defaultProvider = TableServicePlugin.class)
public interface TableService {

	/**
	 * Creates a table view using the given model. This version does not create markers.
	 * @param componentProviderTitle The title of the view
	 * @param tableTypeName The name of the table's type.  This is used to group like tables 
	 *        together
	 * @param model the data model
	 * @param windowSubMenu the name of a sub-menu to use in the "windows" menu.
	 * @param navigatable the component to navigate.  If null, the "connected" components will
	 *        navigate.
	 * @return a provider to show a visible component for the data
	 */
	public <T> TableComponentProvider<T> showTable(String componentProviderTitle,
			String tableTypeName, GhidraProgramTableModel<T> model, String windowSubMenu,
			Navigatable navigatable);

	/**
	 * Creates a table view using the given model. This version creates markers.
	 * @param componentProviderTitle The title of the view
	 * @param tableTypeName The name of the table's type.  This is used to group like tables 
	 *        together
	 * @param model the data model
	 * @param markerColor the color to use for the marker
	 * @param markerIcon the icon to associate with the marker set.
	 * @param windowSubMenu the name of a sub-menu to use in the "windows" menu.
	 * @param navigatable the component to navigate.  If null, the "connected" components will
	 *        navigate.
	 * @return a provider to show a visible component for the data
	 */
	public <T> TableComponentProvider<T> showTableWithMarkers(String componentProviderTitle,
			String tableTypeName, GhidraProgramTableModel<T> model, Color markerColor,
			ImageIcon markerIcon, String windowSubMenu, Navigatable navigatable);

	public TableChooserDialog createTableChooserDialog(TableChooserExecutor executor,
			Program program, String name, Navigatable navigatable);

	public TableChooserDialog createTableChooserDialog(TableChooserExecutor executor,
			Program program, String name, Navigatable navigatable, boolean isModal);
}
