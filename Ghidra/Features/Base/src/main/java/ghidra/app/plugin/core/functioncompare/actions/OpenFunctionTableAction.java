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
package ghidra.app.plugin.core.functioncompare.actions;

import java.awt.event.InputEvent;
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import docking.ActionContext;
import docking.action.*;
import docking.widgets.dialogs.TableChooserDialog;
import ghidra.app.plugin.core.functioncompare.FunctionComparisonProvider;
import ghidra.app.plugin.core.functioncompare.MultiFunctionComparisonPanel;
import ghidra.app.plugin.core.functionwindow.FunctionRowObject;
import ghidra.app.plugin.core.functionwindow.FunctionTableModel;
import ghidra.app.services.FunctionComparisonService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.ScaledImageIconWrapper;
import resources.icons.TranslateIcon;
import util.CollectionUtils;

/**
 * Opens a table chooser allowing the user to select functions from the current
 * program. The table displayed uses a {@link FunctionTableModel}.
 * 
 * @see FunctionComparisonService
 */
public class OpenFunctionTableAction extends DockingAction {

	private static final Icon ADD_ICON = ResourceManager.loadImage("images/Plus.png");
	private static final Icon SCALED_ADD_ICON = new ScaledImageIconWrapper(ADD_ICON, 10, 10);
	private static final ImageIcon COMPARISON_ICON =
		ResourceManager.loadImage("images/page_white_c.png");
	private static final Icon TRANSLATED_ADD_ICON = new TranslateIcon(SCALED_ADD_ICON, 8, 1);
	private static final String ADD_COMPARISON_GROUP = "A9_AddToComparison";
	private static final Icon ADD_TO_COMPARISON_ICON =
		new MultiIcon(COMPARISON_ICON, TRANSLATED_ADD_ICON);

	protected PluginTool tool;
	protected ProgramManager programManagerService;
	protected FunctionComparisonService comparisonService;

	/**
	 * Constructor
	 * 
	 * @param tool the plugin tool
	 * @param provider the function comparison provider
	 */
	public OpenFunctionTableAction(PluginTool tool, FunctionComparisonProvider provider) {
		super("Add Functions To Comparison", provider.getOwner());

		this.tool = tool;
		this.programManagerService = tool.getService(ProgramManager.class);
		this.comparisonService = tool.getService(FunctionComparisonService.class);

		setDescription("Add functions to comparison");
		setPopupMenuData(new MenuData(new String[] { "Add functions" },
			ADD_TO_COMPARISON_ICON, ADD_COMPARISON_GROUP));

		ToolBarData newToolBarData =
			new ToolBarData(ADD_TO_COMPARISON_ICON, ADD_COMPARISON_GROUP);
		setToolBarData(newToolBarData);

		HelpLocation helpLocation = new HelpLocation(MultiFunctionComparisonPanel.HELP_TOPIC,
			"Add_To_Comparison");
		setHelpLocation(helpLocation);

		KeyBindingData data = new KeyBindingData('A', InputEvent.SHIFT_DOWN_MASK);
		setKeyBindingData(data);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return context.getComponentProvider() instanceof FunctionComparisonProvider;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (!(context.getComponentProvider() instanceof FunctionComparisonProvider)) {
			return;
		}

		FunctionComparisonProvider provider =
			(FunctionComparisonProvider) context.getComponentProvider();
		Program currentProgram = programManagerService.getCurrentProgram();
		FunctionTableModel model = new FunctionTableModel(tool, currentProgram);
		model.reload(programManagerService.getCurrentProgram());

		TableChooserDialog<FunctionRowObject> diag =
			new TableChooserDialog<>("Select Functions: " + currentProgram.getName(),
				model, true);
		tool.showDialog(diag);
		List<FunctionRowObject> rows = diag.getSelectionItems();
		if (CollectionUtils.isBlank(rows)) {
			return; // the table chooser can return null if the operation was cancelled
		}

		Set<Function> functions =
			rows.stream().map(row -> row.getFunction()).collect(Collectors.toSet());
		comparisonService.compareFunctions(new HashSet<>(functions), provider);
	}
}
