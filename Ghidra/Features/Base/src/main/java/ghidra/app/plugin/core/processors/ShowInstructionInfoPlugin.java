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
package ghidra.app.plugin.core.processors;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JLabel;
import javax.swing.JPanel;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.label.GDLabel;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.program.util.FunctionSignatureFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.*;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Show Instruction Information",
	description = "This plugin shows the raw instruction at the current location."
			+ " The instruction is displayed as it was disassembled without any "
			+ "operands replaced by label references or other adornments."
)
//@formatter:on
public class ShowInstructionInfoPlugin extends ProgramPlugin {

	private static final String CURRENT_INSTRUCTION_PREPEND_STRING = "Current Instruction: ";
	private static final String CURRENT_FUNCTION_APPEND_STRING =
		" (double-click to go to function entry)";

	private static final int MAX_MANUAL_WRAPPER_FILE_COUNT = 5;

	private DockingAction showInfoAction;
	private InstructionInfoProvider connectedProvider;
	private List<InstructionInfoProvider> disconnectedProviders = new ArrayList<>();
	private DockingAction showProcessorManualAction;

	private JLabel instructionLabel;
	private JPanel instructionPanel;
	private JLabel functionLabel;
	private JPanel functionPanel;
	private JLabel addressLabel;
	private JPanel addressPanel;
	private GoToService goToService;

	private ArrayList<File> manualWrapperFiles = new ArrayList<>();

	public ShowInstructionInfoPlugin(PluginTool tool) {

		super(tool, true, false);

		createStatusPanels();
		createActions();
	}

	@Override
	protected void init() {
		goToService = tool.getService(GoToService.class);
	}

	private void createStatusPanels() {
		instructionPanel = new JPanel(new BorderLayout());
		instructionLabel = new GDLabel("                         ");
		instructionPanel.setPreferredSize(
			new Dimension(200, instructionLabel.getPreferredSize().height));
		instructionLabel.setToolTipText(CURRENT_INSTRUCTION_PREPEND_STRING);
		instructionPanel.add(instructionLabel);
		instructionPanel.setName("Current Instruction");
		tool.addStatusComponent(instructionPanel, true, false);

		functionPanel = new JPanel(new BorderLayout());
		functionLabel = new GDLabel("                   ");
		functionLabel.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() != 2) {
					return;
				}

				goToSurroundingFunction();
			}
		});
		functionPanel.setPreferredSize(new Dimension(130, functionLabel.getPreferredSize().height));
		functionLabel.setToolTipText("Current Function");
		functionPanel.add(functionLabel);
		functionPanel.setName("Current Function");
		tool.addStatusComponent(functionPanel, true, false);

		addressPanel = new JPanel(new BorderLayout());
		addressLabel = new GDLabel("          ");
		addressPanel.setPreferredSize(new Dimension(95, addressLabel.getPreferredSize().height));
		addressLabel.setToolTipText("Current Address");
		addressPanel.add(addressLabel);
		addressPanel.setName("Current Address");
		tool.addStatusComponent(addressPanel, true, false);
	}

	private void createActions() {
		showInfoAction = new ShowInfoAction(this);
		tool.addAction(showInfoAction);

		showProcessorManualAction = new ShowProcessorManualAction(this);
		tool.addAction(showProcessorManualAction);
	}

	void browseInstruction(ListingActionContext context) {
		boolean isDynamic =
			context.getProgram() == currentProgram && context.getLocation().equals(currentLocation);

		if (isDynamic) {
			createOrShowConnectedProvider();
			connectedProvider.setProgram(currentProgram);
			connectedProvider.setAddress(context.getAddress());
		}
		else {
			InstructionInfoProvider provider = new InstructionInfoProvider(this, false);
			provider.setProgram(context.getProgram());
			provider.setAddress(context.getAddress());
			provider.show();
		}
	}

	private void createOrShowConnectedProvider() {
		if (connectedProvider == null) {
			connectedProvider = new InstructionInfoProvider(this, true);
			connectedProvider.show();
		}
		else {
			connectedProvider.setVisible(true);
		}
	}

	void showProcessorManual(ProgramActionContext context) {
		Language lang = currentProgram.getLanguage();
		File wrapperFile = null;
		try {
			URL fileURL = getValidUrl(context, lang);
			if (fileURL == null) {
				return;
			}
			wrapperFile = writeWrapperFile(fileURL);
			BrowserLoader.display(wrapperFile.toURI().toURL(), fileURL, tool);
		}
		catch (Exception e) {
			Msg.showError(this, null, "Exception Locating Manual",
				"Exception locating/displaying processor manual for language: " + lang, e);
		}
	}

	private File writeWrapperFile(URL fileURL) throws IOException {
		File f;
		if (manualWrapperFiles.size() < MAX_MANUAL_WRAPPER_FILE_COUNT) {
			f = File.createTempFile("pdfView", ".html");
			f.deleteOnExit();
		}
		else {
			f = manualWrapperFiles.remove(0);
		}
		manualWrapperFiles.add(f);
		try (PrintWriter pw = new PrintWriter(f)) {
			pw.println("<!DOCTYPE html>");
			pw.println("<html lang=\"en\">");
			pw.println("<head><meta charset=\"utf-8\"></head>");
			pw.println("<body style=\"height:100vh;\">");
			pw.println(
				"<embed src=\"" + fileURL.toExternalForm() + "\" width=\"100%\" height=\"100%\">");
			pw.println("</body>");
			pw.println("</html>");
		}
		return f;
	}

	URL getValidUrl(ProgramActionContext context, Language language) throws IOException {

		ManualEntry entry = locateManualEntry(context, language);
		if (entry == null) {
			return null;
		}

		String filename = entry.getManualPath();
		String missingDescription = entry.getMissingManualDescription();
		if (filename == null || !new File(filename).exists()) {
			String message = buildMissingManualMessage(language, filename, missingDescription);
			Msg.showInfo(this, null, "Missing Processor Manual", message);
			return null;
		}

		URL url = new File(filename).toURI().toURL();

		String pageNumber = entry.getPageNumber();
		if (pageNumber != null) {
			// include manual page as query string (respected by PDF readers)
			String fileNameAndPage = url.getFile() + "#page=" + pageNumber;
			url = new URL(url.getProtocol(), null, fileNameAndPage);
		}

		return url;
	}

	ManualEntry locateManualEntry(ProgramActionContext context, Language language) {
		if (language == null || context == null) {
			return null;
		}

		Instruction instruction = null;
		if (context instanceof ListingActionContext) {
			instruction = getInstructionForContext((ListingActionContext) context);
		}
		String mnemonicString = instruction == null ? null : instruction.getMnemonicString();

		//remove underscore at the beginning of instructions which mess up the manual page load
		if (mnemonicString != null && !mnemonicString.isEmpty() &&
			mnemonicString.charAt(0) == '_') {
			mnemonicString = mnemonicString.substring(1);
		}

		ManualEntry entry = language.getManualEntry(mnemonicString);
		if (entry != null) {
			return entry;
		}

		Msg.showError(this, null, "No Processor Manual",
			"Couldn't find processor manual for language: " + language);
		return null;
	}

	private String buildMissingManualMessage(Language language, String filename,
			String missingDescription) {
		StringBuffer buf = new StringBuffer(HTMLUtilities.HTML);
		buf.append("Ghidra could not find the processor manual for ").append(language);
		buf.append(HTMLUtilities.BR);
		buf.append(HTMLUtilities.BR);
		buf.append(
			"Note: The Ghidra distribution does not include some of the processor manuals due to copyright issues. ");
		buf.append(HTMLUtilities.BR);
		buf.append("Most of these manuals are readily available on-line.");
		buf.append(HTMLUtilities.BR);
		buf.append(HTMLUtilities.BR);
		buf.append(
			"To correct this issue, obtain the manual described below and place it at the specified location. ");
		buf.append(HTMLUtilities.BR);
		buf.append(HTMLUtilities.BR);
		buf.append("Manual information: ");
		buf.append(HTMLUtilities.bold(missingDescription));
		buf.append(HTMLUtilities.BR);
		buf.append(HTMLUtilities.BR);
		buf.append("Location to place manual file: ");
		buf.append(HTMLUtilities.bold(filename));
		buf.append(HTMLUtilities.BR);
		buf.append(HTMLUtilities.BR);
		buf.append("Contact the Ghidra team if you have any problems.");
		return buf.toString();
	}

	/**
	 * @see ghidra.framework.plugintool.Plugin#dispose()
	 */
	@Override
	public void dispose() {
		if (connectedProvider != null) {
			connectedProvider.dispose();
		}

		for (InstructionInfoProvider provider : disconnectedProviders) {
			provider.dispose();
		}
		disconnectedProviders.clear();
		tool.removeStatusComponent(instructionPanel);
		tool.removeStatusComponent(addressPanel);
		tool.removeStatusComponent(functionPanel);
		super.dispose();
	}

	/**
	 * Remove this InstructionProvider from list of managed dialogs
	 *
	 * @param provider
	 */
	public void remove(InstructionInfoProvider provider) {
		if (provider == connectedProvider) {
			connectedProvider = null;
		}
		else {
			disconnectedProviders.remove(provider);
		}
		provider.dispose();
	}

	JLabel getInstructionLabel() {
		return instructionLabel;
	}

	/**
	 * Subclass should override this method if it is interested in
	 * program location events.
	 * @param loc location could be null
	 */
	@Override
	protected void locationChanged(ProgramLocation loc) {
		if (connectedProvider != null) {
			connectedProvider.setAddress(loc == null ? null : loc.getAddress());
		}
		if (loc == null || loc.getAddress() == null) {
			addressLabel.setText("");
			functionLabel.setText("");
			return;
		}
		addressLabel.setText(loc.getAddress().toString(false));

		Function currentFunction =
			currentProgram.getListing().getFunctionContaining(currentLocation.getAddress());
		boolean insideFunction = currentFunction != null;
		if (insideFunction) {
			functionLabel.setText(" " + currentFunction.getName() + " ");
			functionLabel.setToolTipText(
				currentFunction.getName() + CURRENT_FUNCTION_APPEND_STRING);
		}
		else {
			functionLabel.setText("");
			functionLabel.setToolTipText("");
		}

		/// code added //
		Instruction instr = getInstructionForCurrentProgram();
		if (instr == null) {
			instructionLabel.setText("");
			instructionLabel.setToolTipText("");
			return;
		}

		String representation = instr.toString();
		instructionLabel.setText(" " + representation + " ");
		instructionLabel.setToolTipText(CURRENT_INSTRUCTION_PREPEND_STRING + representation);

		// end code added ///
	}

	@Override
	protected void programActivated(Program program) {
		if (connectedProvider != null) {
			connectedProvider.setProgram(program);
		}
	}

	@Override
	protected void programClosed(Program program) {
		for (InstructionInfoProvider provider : new ArrayList<>(disconnectedProviders)) {
			if (provider.getProgram() == program) {
				remove(provider);
			}
		}
	}

	@Override
	protected void programDeactivated(Program program) {
		instructionLabel.setText("");
		instructionLabel.setToolTipText("");
		if (connectedProvider != null) {
			connectedProvider.setProgram(null);
		}
	}

	Instruction getInstructionForContext(ListingActionContext context) {
		Address addr = context.getAddress();
		if (addr == null) {
			return null;
		}

		Program program = context.getProgram();
		Listing listing = program.getListing();
		return listing.getInstructionContaining(addr);
	}

	private Instruction getInstructionForCurrentProgram() {
		Address addr = currentLocation.getAddress();
		if (addr == null) {
			return null;
		}

		Listing listing = currentProgram.getListing();
		return listing.getInstructionContaining(addr);
	}

	void goToSurroundingFunction() {
		if (goToService == null || currentProgram == null) {
			return;
		}

		Function currentFunction =
			currentProgram.getListing().getFunctionContaining(currentLocation.getAddress());
		if (currentFunction != null) {
			goToService.goTo(
				new FunctionSignatureFieldLocation(currentProgram, currentFunction.getEntryPoint(),
					null, 0, currentFunction.getPrototypeString(false, false)));
		}
	}

	void dynamicStateChanged(InstructionInfoProvider provider, boolean isDynamic) {
		if (provider == connectedProvider && !isDynamic) {
			disconnectedProviders.add(provider);
			connectedProvider = null;
		}
		else if (provider != connectedProvider && isDynamic) {
			if (connectedProvider != null) {
				connectedProvider.setNonDynamic();
			}
			disconnectedProviders.remove(provider);
			connectedProvider = provider;
			connectedProvider.setProgram(currentProgram);
			Address address = currentLocation == null ? null : currentLocation.getAddress();
			connectedProvider.setAddress(address);
		}
	}

}

class ShowInfoAction extends ListingContextAction {
	ShowInstructionInfoPlugin plugin = null;

	public ShowInfoAction(ShowInstructionInfoPlugin plugin) {

		super("Show Instruction Info", plugin.getName());

		this.plugin = plugin;

		setPopupMenuData(new MenuData(new String[] { "Instruction Info..." }, null, "Disassembly"));

	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		plugin.browseInstruction(context);
	}
}

/**
 * Action class for displaying the processor manual (PDF file)
 */
class ShowProcessorManualAction extends ProgramContextAction {
	private ShowInstructionInfoPlugin plugin = null;

	public ShowProcessorManualAction(ShowInstructionInfoPlugin plugin) {
		super("Show Processor Manual", plugin.getName());

		this.plugin = plugin;

		setMenuBarData(
			new MenuData(new String[] { "Tools", "Processor Manual..." }, null, "Disassembly"));
		setPopupMenuData(new MenuData(new String[] { "Processor Manual..." }, null, "Disassembly"));

		this.setEnabled(true);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return (context instanceof ListingActionContext);
	}

	@Override
	public void actionPerformed(ProgramActionContext context) {
		plugin.showProcessorManual(context);
	}
}
