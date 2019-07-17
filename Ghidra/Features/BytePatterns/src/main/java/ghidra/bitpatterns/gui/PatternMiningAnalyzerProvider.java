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
package ghidra.bitpatterns.gui;

import java.awt.Component;
import java.util.List;

import javax.swing.ImageIcon;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.bitpatterns.info.*;
import ghidra.closedpatternmining.SequenceMiningParams;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

/**
 * 
 * This class extends {@link ByteSequenceAnalyzerProvider} by adding actions
 * related to mining closed sequential patterns.
 *  
 */
public class PatternMiningAnalyzerProvider extends ByteSequenceAnalyzerProvider {

	private static final String TITLE = "Analyzing Sequences";
	private static final String MINE_PATTERNS_BUTTON_TEXT = "Mine Closed Sequential Patterns";
	private static final String ENTER_PARAMS_TITLE = "Set Mining Parameters";

	private DockingAction mineClosedPatternsAction;

	/**
	 * Create a provider for analyzing byte sequences with the option to mine selected sequences
	 * for closed patterns
	 * @param plugin plugin
	 * @param rowObjects byte sequences to mine
	 * @param parent parent componet
	 * @param type sequence type
	 * @param cRegFilter {@code ContextRegisterFilter} applied to sequences
	 */
	public PatternMiningAnalyzerProvider(FunctionBitPatternsExplorerPlugin plugin,
			List<ByteSequenceRowObject> rowObjects, Component parent, PatternType type,
			ContextRegisterFilter cRegFilter) {
		super(TITLE, plugin, rowObjects, parent, type, cRegFilter, null);
		HelpLocation helpLocation = new HelpLocation("FunctionBitPatternsExplorerPlugin",
			"Mining_Closed_Sequential_Patterns");
		setHelpLocation(helpLocation);
		addMiningAction();
	}

	private void addMiningAction() {
		mineClosedPatternsAction = new DockingAction(MINE_PATTERNS_BUTTON_TEXT, title) {
			@Override
			public void actionPerformed(ActionContext context) {
				List<ByteSequenceRowObject> lastSelectedObjects =
					byteSequenceTable.getLastSelectedObjects();
				SequenceMiningParamsInputDialog paramsCreater =
					new SequenceMiningParamsInputDialog(ENTER_PARAMS_TITLE, mainPanel);
				if (paramsCreater.isCanceled()) {
					return;
				}
				SequenceMiningParams params = paramsCreater.getSequenceMiningParams();
				List<ClosedPatternRowObject> closedPatternRowObjects =
					ClosedPatternRowObject.mineClosedPatterns(lastSelectedObjects,
						params.getMinPercentage(), params.getRequiredBitsOfCheck(),
						params.getUseBinary(), type, cRegFilter, mainPanel);
				new ClosedPatternTableDialog(plugin, closedPatternRowObjects, mainPanel, type,
					cRegFilter);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				List<ByteSequenceRowObject> lastSelectedObjects =
					byteSequenceTable.getLastSelectedObjects();
				if (lastSelectedObjects == null) {
					return false;
				}
				if (lastSelectedObjects.isEmpty()) {
					return false;
				}
				return true;
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}

		};
		ImageIcon icon = ResourceManager.loadImage("images/magnifier.png");
		mineClosedPatternsAction.setPopupMenuData(
			new MenuData(new String[] { "Mine Sequential Patterns" }, icon));
		mineClosedPatternsAction.setDescription("Mine Sequential Patterns");
		this.addAction(mineClosedPatternsAction);
		HelpLocation helpLocation = new HelpLocation("FunctionBitPatternsExplorerPlugin",
			"Mining_Closed_Sequential_Patterns");
		mineClosedPatternsAction.setHelpLocation(helpLocation);
	}

	@Override
	ByteSequenceTableModel createByteSequenceTable(FunctionBitPatternsExplorerPlugin fPlugin,
			List<ByteSequenceRowObject> rowObjects) {
		return new ByteSequenceTableModel(plugin, rowObjects);

	}

}
