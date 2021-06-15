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
package ghidra.app.plugin.core.hover;

import static ghidra.util.HTMLUtilities.*;

import java.awt.*;

import javax.swing.JComponent;
import javax.swing.JToolTip;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.plugin.core.gotoquery.GoToHelper;
import ghidra.app.services.CodeFormatService;
import ghidra.app.util.*;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;
import ghidra.util.bean.opteditor.OptionsVetoException;

/**
 * A hover service to show tool tip text for hovering over a reference.
 */
public abstract class AbstractReferenceHover extends AbstractConfigurableHover {

	private static final int WINDOW_OFFSET = 50;
	private static final Color BACKGROUND_COLOR = new Color(255, 255, 230);

	private CodeFormatService codeFormatService;
	private ListingPanel panel;
	private JToolTip toolTip;
	private ProgramLocation previewLocation;
	private GoToHelper gotoHelper;

	public AbstractReferenceHover(PluginTool tool, int priority) {
		this(tool, null, priority);
	}

	protected AbstractReferenceHover(PluginTool tool, CodeFormatService codeFormatService,
			int priority) {
		super(tool, priority);
		this.codeFormatService = codeFormatService;
		initialize();
	}

	@Override
	public void dispose() {
		super.dispose();

		if (panel != null) {
			panel.dispose();
			panel = null;
		}
		if (gotoHelper != null) {
			gotoHelper.dispose();
			gotoHelper = null;
		}
	}

	private void initialize() {
		gotoHelper = new GoToHelper(tool);
	}

	@Override
	public void initializeOptions() {

		options = tool.getOptions(getOptionsCategory());

		options.setOptionsHelpLocation(new HelpLocation(HelpTopics.CODE_BROWSER, "MouseHover"));
		HelpLocation help = new HelpLocation(HelpTopics.CODE_BROWSER, "ReferenceHover");

		String hoverName = getName();
		options.getOptions(hoverName).setOptionsHelpLocation(help);

		options.registerOption(hoverName, true, null, getDescription());
		enabled = options.getBoolean(hoverName, true);

		options.registerOption(hoverName + Options.DELIMITER + "Dialog Height", 400, help,
			"Height of the popup window");
		options.registerOption(hoverName + Options.DELIMITER + "Dialog Width", 600, help,
			"Width of the popup window");

		options.addOptionsChangeListener(this);
	}

	@Override
	public void setOptions(Options options, String optionName) {

		String hoverName = getName();
		if (optionName.equals(hoverName)) {
			enabled = options.getBoolean(hoverName, true);
			return;
		}

		String widthOptionName = optionName + Options.DELIMITER + "Dialog Width";
		String heightOptionName = optionName + Options.DELIMITER + "Dialog Height";

		if (optionName.equals(widthOptionName) ||
			optionName.equals(heightOptionName)) {
			int dialogWidth = options.getInt(widthOptionName, 600);
			if (dialogWidth <= 0) {
				throw new OptionsVetoException(
					"Reference Code Viewer Dialog Width must be greater than 0");
			}
			int dialogHeight = options.getInt(heightOptionName, 400);
			if (dialogHeight <= 0) {
				throw new OptionsVetoException(
					"Reference Code Viewer Dialog Height must be greater than 0");
			}

			Dimension d = new Dimension(dialogWidth, dialogHeight);
			if (panel != null) {
				panel.setPreferredSize(d);
			}
		}
	}

	/**
	 * initializeLazily() should get called to try to get the CodeFormatService and create the panel
	 * the first time we want to use the panel.
	 */
	protected void initializeLazily() {
		if (panel != null) {
			return;
		}
		if (tool == null) {
			return;
		}
		if (codeFormatService == null) {
			codeFormatService = tool.getService(CodeFormatService.class);
		}
		if (codeFormatService == null) {
			return;
		}

		toolTip = new JToolTip();

		panel = new ListingPanel(codeFormatService.getFormatManager());// share the manager from the code viewer
		panel.setTextBackgroundColor(BACKGROUND_COLOR);

		String name = getName();
		String widthOptionName = name + Options.DELIMITER + "Dialog Width";
		String heightOptionName = name + Options.DELIMITER + "Dialog Height";
		int dialogWidth = options.getInt(widthOptionName, 600);
		int dialogHeight = options.getInt(heightOptionName, 400);
		Dimension d = new Dimension(dialogWidth, dialogHeight);
		panel.setPreferredSize(d);
	}

	@Override
	public JComponent getHoverComponent(Program program, ProgramLocation programLocation,
			FieldLocation fieldLocation, Field field) {

		initializeLazily();
		if (!enabled || programLocation == null || panel == null) {
			return null;
		}

		Address refAddr = programLocation.getRefAddress();
		if (refAddr != null && refAddr.isExternalAddress()) {
			return createExternalToolTipComponent(program, refAddr);
		}

		previewLocation =
			getPreviewLocation(program, programLocation, programLocation.getRefAddress());
		if (previewLocation == null) {
			return null;
		}

		panel.setProgram(program); // the program must be set in order for the goto to work
		boolean validLocation = panel.goTo(previewLocation);
		if (validLocation) {
			Rectangle bounds = panel.getBounds();
			bounds.x = WINDOW_OFFSET;
			bounds.y = WINDOW_OFFSET;
			panel.setBounds(bounds);
			return panel;
		}
		panel.setProgram(null);

		// At this point we have a program location, but we could not go there.  This can happen
		// if the location is not in memory.
		return createOutOfMemoryToolTipComponent(previewLocation);
	}

	protected JComponent createExternalToolTipComponent(Program program, Address extAddr) {

		Symbol s = program.getSymbolTable().getPrimarySymbol(extAddr);
		if (s == null) {
			return null;
		}

		ExternalLocation extLoc = null;
		Function extFunc = null;
		Object obj = s.getObject();
		if (obj instanceof Function) {
			extFunc = (Function) obj;
			extLoc = extFunc.getExternalLocation();
		}
		else if (obj instanceof ExternalLocation) {
			extLoc = (ExternalLocation) obj;
		}
		else {
			return null;
		}

		toolTip.setTipText(ToolTipUtils.getToolTipText(extLoc, true));
		return toolTip;
	}

	protected JComponent createOutOfMemoryToolTipComponent(ProgramLocation location) {

		/*
		 		Format
		 	
		 	Address: ram:1234
		 	Address not in memory
		 	
		 	
		 		Or, when multiple symbols at destination
		 		
		 		
		 	Address: ram:1234
		 	Symbols (3): 
		 		foo
		 		bar
		 		baz
		 	Address not in memory
		 	
		 */

		String newline = HTMLUtilities.HTML_NEW_LINE;
		StringBuilder buffy = new StringBuilder(HTML);
		buffy.append("Address: ");
		String addressString = location.getAddress().toString(true, false);
		addressString = HTMLUtilities.friendlyEncodeHTML(addressString);
		buffy.append(addressString);
		buffy.append(newline);

		Program p = location.getProgram();
		SymbolTable st = p.getSymbolTable();
		Symbol[] symbols = st.getSymbols(location.getAddress());

		if (symbols.length > 1) {
			buffy.append("Symbols (").append(symbols.length).append("): ").append(newline);
			String pad = HTMLUtilities.spaces(4);
			SymbolInspector inspector = new SymbolInspector(tool, null);
			for (Symbol s : symbols) {
				ColorAndStyle style = inspector.getColorAndStyle(s);
				String name = s.getName(true);
				name = pad + HTMLUtilities.friendlyEncodeHTML(name);
				String html = style.toHtml(name);
				buffy.append(html).append(newline);
			}
		}

		String message = "Address not in memory";
		message = HTMLUtilities.italic(message);
		message = HTMLUtilities.colorString(Color.GRAY, message);
		buffy.append(message);
		toolTip.setTipText(buffy.toString());
		return toolTip;
	}

	public void programClosed(Program program) {
		if (panel != null && panel.getProgram() == program) {
			panel.setProgram(null);
		}
	}

	@Override
	public void componentHidden() {
		if (panel != null) {
			panel.setProgram(null);
		}
	}

	@Override
	public void componentShown() {
		if (panel != null && previewLocation != null) {
			panel.goTo(previewLocation);
		}
	}

	// gets the referred to location from the given location and address
	protected ProgramLocation getPreviewLocation(Program program, ProgramLocation pLoc,
			Address toAddress) {
		if (toAddress == null || pLoc == null) {
			return null;
		}

		ProgramLocation location = gotoHelper.getLocation(program, pLoc.getAddress(), toAddress);
		if (location != null) {
			return location;
		}

		if (pLoc instanceof OperandFieldLocation && toAddress.isVariableAddress()) {
			OperandFieldLocation opLoc = (OperandFieldLocation) pLoc;
			ReferenceManager refMgr = program.getReferenceManager();
			Reference ref =
				refMgr.getReference(opLoc.getAddress(), toAddress, opLoc.getOperandIndex());
			if (ref != null) {
				Variable var = refMgr.getReferencedVariable(ref);
				if (var != null) {
					return new VariableNameFieldLocation(program, var, 0);
				}
			}
		}
		return null;
	}

	@Override
	public void scroll(int amount) {
		if (panel != null) {
			panel.getFieldPanel().scrollView(amount);
		}
	}

}
