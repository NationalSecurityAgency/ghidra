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

package ghidra.app.plugin.core.pcodepatch;

import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

/**
 * A plugin for pcode patching
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.PATCHING,
    shortDescription = "Pcode Patch",
    description = "This plugin provides functionality for pcode patching."
)
//@formatter:on
public class PcodePatchPlugin extends ProgramPlugin {
    public static final String PCODE_PATCH_NAME = "Pcode Patch";

    static final String SUBMENU_NAME = "Pcode Patch";
    static final String PCODE_PATCH_GROUP = "pcodepatch";

    private DockingAction pcodePatchAction;
    private DockingAction pcodeInsertBeforeAction;
    private DockingAction pcodeInsertAfterAction;
    private DockingAction pcodePatchResetAction;
    private DockingAction pcodeRemoveAction;

    public PcodePatchPlugin(PluginTool tool) {
        super(tool, false, false, false);
        createActions();
    }

    private void createActions() {
        tool.setMenuGroup(new String[] { SUBMENU_NAME }, PCODE_PATCH_GROUP);

        pcodePatchAction = new PcodePatchAction("Patch Current Pcode", getName(), this);
        pcodePatchAction.setPopupMenuData(
            new MenuData(new String[] { SUBMENU_NAME, "Patch..."})
        );
        pcodeInsertBeforeAction = new PcodeInsertBeforeAction("Insert Pcode Before", getName(), this);
        pcodeInsertBeforeAction.setPopupMenuData(
            new MenuData(new String[] { SUBMENU_NAME, "Insert Before..."})
        );
        pcodeInsertAfterAction = new PcodeInsertAfterAction("Insert Pcode After", getName(), this);
        pcodeInsertAfterAction.setPopupMenuData(
            new MenuData(new String[] { SUBMENU_NAME, "Insert After..."})
        );
        pcodeRemoveAction = new PcodeRemoveAction("Remove Pcode", getName(), this);
        pcodeRemoveAction.setPopupMenuData(
            new MenuData(new String[] { SUBMENU_NAME, "Remove Pcode At..."})
        );
        pcodePatchResetAction = new PcodePatchResetAction("Reset Pcode", getName(), this);
        pcodePatchResetAction.setPopupMenuData(
            new MenuData(new String[] { SUBMENU_NAME, "Reset Pcode"})
        );

        pcodePatchAction.setEnabled(true);
        pcodeInsertBeforeAction.setEnabled(true);
        pcodeInsertAfterAction.setEnabled(true);
        pcodeRemoveAction.setEnabled(true);
        pcodePatchResetAction.setEnabled(true);

        tool.addAction(pcodePatchAction);
        tool.addAction(pcodeInsertBeforeAction);
        tool.addAction(pcodeInsertAfterAction);
        tool.addAction(pcodeRemoveAction);
        tool.addAction(pcodePatchResetAction);
    }

    @Override
    protected void dispose() {
        pcodePatchAction.dispose();
        pcodeInsertBeforeAction.dispose();
        pcodeInsertAfterAction.dispose();
        pcodeRemoveAction.dispose();
        pcodePatchResetAction.dispose();
    }
}
