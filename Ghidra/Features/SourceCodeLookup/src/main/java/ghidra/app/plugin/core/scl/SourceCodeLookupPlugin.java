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
package ghidra.app.plugin.core.scl;

import java.awt.event.KeyEvent;
import java.io.*;
import java.net.Socket;

import docking.ActionContext;
import docking.action.*;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.decompiler.*;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.eclipse.EclipseConnection;
import ghidra.app.plugin.core.eclipse.EclipseIntegrationOptionsPlugin;
import ghidra.app.plugin.core.navigation.locationreferences.*;
import ghidra.app.services.EclipseIntegrationService;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.MISC,
	shortDescription = "Source Code Lookup Plugin",
	description = "Plugin to send requests to the development IDE to lookup symbols in source files.",
	servicesRequired = { EclipseIntegrationService.class },
	eventsConsumed = { ProgramLocationPluginEvent.class }
)
//@formatter:on
public class SourceCodeLookupPlugin extends ProgramPlugin {

	private static final String ACTION_NAME = "Go To Symbol Source";

	private static final String CDT_START = "org.eclipse.cdt.core_";

	private DockingAction lookupSourceCodeAction;

	public SourceCodeLookupPlugin(PluginTool tool) {
		super(tool, false, false);
	}

	@Override
	protected void dispose() {
		super.dispose();
	}

	@Override
	public void init() {
		super.init();

		lookupSourceCodeAction = new DockingAction("Source Code Lookup", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				lookupSymbol();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return context instanceof ProgramLocationActionContext;
			}
		};

		// put the menu bar data with the GoTo action group--at the end
		lookupSourceCodeAction.setMenuBarData(
			new MenuData(new String[] { ToolConstants.MENU_NAVIGATION, ACTION_NAME }, null, "GoTo",
				MenuData.NO_MNEMONIC, "z"));

		// TODO: having this action in the decompiler and the listing causes issues in terms of
		// how to define the group/menu position.  For now, just put the menu in the main menu bar.
		// lookupSourceCodeAction.setPopupMenuData(new MenuData(POPUP_PATH, null, "Label",
		// MenuData.NO_MNEMONIC, "z"));
		lookupSourceCodeAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_F3, 0));
		lookupSourceCodeAction.setHelpLocation(
			new HelpLocation("SourceCodeLookupPlugin", "Source_Code_Lookup_Plugin"));
		tool.addAction(lookupSourceCodeAction);
	}

	private void lookupSymbol() {

		String symbolText = getSymbolText();
		if (symbolText == null) {
			return;
		}

		String demangled = attemptToDemangle(symbolText);
		if (demangled != null) {
			symbolText = demangled;
		}

		EclipseIntegrationService service = tool.getService(EclipseIntegrationService.class);
		ToolOptions options = service.getEclipseIntegrationOptions();
		int port = options.getInt(EclipseIntegrationOptionsPlugin.SYMBOL_LOOKUP_PORT_OPTION, -1);
		if (port < 0 || port > Short.MAX_VALUE) {
			service.handleEclipseError(
				"Option \"" + EclipseIntegrationOptionsPlugin.SYMBOL_LOOKUP_PORT_OPTION +
					"\" is not valid.  Cannot connect to Eclipse.",
				true, null);
			return;
		}
		while (true) {
			EclipseConnection connection = service.connectToEclipse(port);
			Socket clientSocket = connection.getSocket();
			if (clientSocket == null) {
				handleUnableToConnect(connection);
				return;
			}
			try (BufferedReader input =
				new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
					PrintStream output = new PrintStream(clientSocket.getOutputStream())) {

				output.print(symbolText + "\n");
				output.flush();

				String reply = input.readLine();
				Msg.debug(this, reply);
				tool.setStatusInfo(reply);

				if (symbolText.startsWith("_")) {
					symbolText = symbolText.substring(1);
				}
				else {
					break;
				}
			}
			catch (IOException e) {
				// shouldn't happen
				Msg.showError(this, null, "Unexpected Exception",
					"Unexpected exception " + "connecting to source lookup editor", e);
				return;
			}
			finally {
				try {
					clientSocket.close();
				}
				catch (IOException e) {
					// Nothing to do
				}
			}
		}
	}

	private String getSymbolText() {
		String symbolText = null;

		if (currentLocation instanceof DecompilerLocation) {
			DecompilerLocation decompilerLocation = (DecompilerLocation) currentLocation;
			ClangToken token = decompilerLocation.getToken();
			if (token == null) {
				return null;
			}

			if (token instanceof ClangFieldToken || token instanceof ClangFuncNameToken ||
				token instanceof ClangLabelToken || token instanceof ClangTypeToken) {
				symbolText = token.getText();
			}

// TODO: we could improve the logic for finding lookup text: we could use the datatype values,
//	     like those below to make a better name.  There could be other tricks we could do,
//		 depending upon the token type and its information.  For now, just use the text for types
//	     that may be valid.
//
//				if (symbolText == null) {
//					if (token instanceof ClangFieldToken) {
//						symbolText = tokenName;
//					}
//					else if (token instanceof ClangTypeToken) {
//						symbolText = tokenName;
//					}
//				}
//			}

		}
		else {
			LocationDescriptor locationDescriptor =
				ReferenceUtils.getLocationDescriptor(currentLocation);
			if (locationDescriptor == null) {
				return null;
			}
			symbolText = getSymbolTextFromLocation(locationDescriptor);
		}
		return symbolText;
	}

	private String getSymbolTextFromLocation(LocationDescriptor locationDescriptor) {
		if (locationDescriptor.getClass() == AddressLocationDescriptor.class) {
			return null;
		}
		return locationDescriptor.getLabel();
	}

	private String attemptToDemangle(String nameToDemangle) {
		if (nameToDemangle == null) {
			return null;
		}
		DemangledObject demangledObject = DemanglerUtil.demangle(nameToDemangle);
		if (demangledObject != null) {
			return demangledObject.getName();
		}
		return null;
	}

	private void handleUnableToConnect(EclipseConnection connection) {
		EclipseIntegrationService service = tool.getService(EclipseIntegrationService.class);
		try {
			if (!service.isEclipseFeatureInstalled(
				(dir, filename) -> filename.startsWith(CDT_START))) {
				Msg.showWarn(this, null, "No CDT Installed",
					"No CDT installed in Eclipse. You must install the CDT before\n" +
						"using the source code lookup plugin.");
				return;
			}
		}
		catch (FileNotFoundException e) {
			// Eclipse is not installed.
		}

		if (connection.getProcess() != null) {
			Msg.showWarn(this, null, "Ports May Not Match",
				"The port used by Ghidra may not match the port used by Eclipse.\nMake sure " +
					"the port in the Ghidra options (Edit -> Tool Options... -> Source Code Lookup) \n" +
					"matches the port in the Eclipse preference page " +
					"(Preferences -> Ghidra -> Ghidra Symbol Lookup).");
		}
	}
}
