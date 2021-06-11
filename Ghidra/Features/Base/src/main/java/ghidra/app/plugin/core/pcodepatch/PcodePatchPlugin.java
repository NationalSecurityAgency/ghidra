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

        pcodePatchAction.setEnabled(true);
        pcodeInsertBeforeAction.setEnabled(true);
        pcodeInsertAfterAction.setEnabled(true);

        tool.addAction(pcodePatchAction);
        tool.addAction(pcodeInsertBeforeAction);
        tool.addAction(pcodeInsertAfterAction);
    }

    @Override
    protected void dispose() {
        pcodePatchAction.dispose();
        pcodeInsertBeforeAction.dispose();
        pcodeInsertAfterAction.dispose();
    }
}
