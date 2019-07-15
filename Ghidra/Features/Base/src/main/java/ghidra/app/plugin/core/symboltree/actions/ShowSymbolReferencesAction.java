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
package ghidra.app.plugin.core.symboltree.actions;

import javax.swing.KeyStroke;
import javax.swing.tree.TreePath;

import docking.action.*;
import ghidra.app.actions.AbstractFindReferencesDataTypeAction;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesService;
import ghidra.app.plugin.core.symboltree.SymbolTreeActionContext;
import ghidra.app.plugin.core.symboltree.nodes.*;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.ServiceListener;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.FunctionSignatureFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.Swing;

public class ShowSymbolReferencesAction extends SymbolTreeContextAction {

	private PluginTool tool;

	/** We need this when our plugin is loaded before the service we are using */
	private ServiceListener helpLocationServiceListener = new ServiceListener() {

		@Override
		public void serviceRemoved(Class<?> interfaceClass, Object service) {
			// don't care
		}

		@Override
		public void serviceAdded(Class<?> interfaceClass, Object service) {
			if (interfaceClass.equals(LocationReferencesService.class)) {
				setHelpLocation(((LocationReferencesService) service).getHelpLocation());
				Swing.runLater(() -> tool.removeServiceListener(this));
			}
		}
	};

	public ShowSymbolReferencesAction(PluginTool tool, String owner) {
		super(AbstractFindReferencesDataTypeAction.NAME, owner, KeyBindingType.SHARED);
		this.tool = tool;

		setPopupMenuData(new MenuData(new String[] { "Show References to" }, "0Middle"));

		installHelpLocation();

		KeyStroke defaultkeyStroke = AbstractFindReferencesDataTypeAction.DEFAULT_KEY_STROKE;
		initKeyStroke(defaultkeyStroke);
	}

	private void initKeyStroke(KeyStroke keyStroke) {
		if (keyStroke == null) {
			return;
		}

		setKeyBindingData(new KeyBindingData(keyStroke));
	}

	private void installHelpLocation() {
		LocationReferencesService locationReferencesService =
			tool.getService(LocationReferencesService.class);
		if (locationReferencesService == null) {
			// not installed yet; listen for the service to be installed
			tool.addServiceListener(helpLocationServiceListener);
			return;
		}

		// this action is really just a pass through for the service
		setHelpLocation(locationReferencesService.getHelpLocation());
	}

	@Override
	protected boolean isEnabledForContext(SymbolTreeActionContext context) {

		LocationReferencesService locationReferencesService =
			tool.getService(LocationReferencesService.class);
		if (locationReferencesService == null) {
			return false;
		}

		TreePath[] selectionPaths = context.getSelectedSymbolTreePaths();
		if (selectionPaths.length != 1) {
			return false;
		}

		Object lastPathComponent = selectionPaths[0].getLastPathComponent();
		if (lastPathComponent instanceof CodeSymbolNode ||
			lastPathComponent instanceof FunctionSymbolNode ||
			lastPathComponent instanceof LibrarySymbolNode ||
			lastPathComponent instanceof LocalVariableSymbolNode ||
			lastPathComponent instanceof ParameterSymbolNode) {
			return true;
		}

		// TODO multi reference type
		// ClassSymbolNode - maybe could be both when classes are real things in Ghidra
		// NamespaceSymbolNode
		// FunctionSymbolNode - could be both

		return false;
	}

	@Override
	protected void actionPerformed(SymbolTreeActionContext context) {

		LocationReferencesService locationReferencesService =
			tool.getService(LocationReferencesService.class);

		CodeViewerService codeViewerService = tool.getService(CodeViewerService.class);
		Navigatable navigatable = codeViewerService.getNavigatable();

		TreePath[] selectionPaths = context.getSelectedSymbolTreePaths();
		SymbolNode symbolNode = (SymbolNode) selectionPaths[0].getLastPathComponent();
		ProgramLocation location = getProgramLocation(symbolNode);
		if (location == null) {
			Msg.debug(this, "Do not know how to show references to SymbolNode type: " + symbolNode);
			return;
		}

		locationReferencesService.showReferencesToLocation(location, navigatable);
	}

	private ProgramLocation getProgramLocation(SymbolNode symbolNode) {
		Symbol symbol = symbolNode.getSymbol();
		if (symbol instanceof FunctionSymbol) {
			return new FunctionSignatureFieldLocation(symbol.getProgram(), symbol.getAddress());
		}
		return symbol.getProgramLocation();
	}

}
