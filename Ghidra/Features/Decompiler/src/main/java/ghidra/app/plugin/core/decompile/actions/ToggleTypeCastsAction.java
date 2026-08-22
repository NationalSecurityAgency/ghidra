package ghidra.app.plugin.core.decompile.actions;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.options.OptionsService;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;

public class ToggleTypeCastsAction extends DockingAction  {
	private final static String OPTIONS_TITLE = "Decompiler";
	private final static String OPTION_PRINT_TYPE_CASTS = "Display.Disable printing of type casts";

	private final PluginTool tool;

	public ToggleTypeCastsAction(String owner, PluginTool tool) {
		super("Toggle Printing of Type Casts", owner);

		this.tool = tool;
		setPopupMenuData(new MenuData( new String[]{ "Toggle Printing of Type Casts" }, "ZED" ));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return tool.getService(OptionsService.class) != null;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		final OptionsService service = tool.getService(OptionsService.class);
		final ToolOptions options = service.getOptions(OPTIONS_TITLE);
		final boolean b = options.getBoolean(OPTION_PRINT_TYPE_CASTS, false);
		options.setBoolean(OPTION_PRINT_TYPE_CASTS, !b);
	}

}
