package ghidra.app.plugin.core.decompile.actions;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.decompiler.component.HighlightToken;
import ghidra.app.decompiler.component.HighlightTokenObservableList;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.listing.Function;
import ghidra.util.HelpLocation;
import ghidra.util.UndefinedFunction;

public class RemoveAllHighlightsAction extends DockingAction {
	private DecompilerPanel panel;
	private DecompilerController controller;
	
	public RemoveAllHighlightsAction(String owner, DecompilerController controller) {
		this(owner, controller, false);
	}

	public RemoveAllHighlightsAction(String owner, DecompilerController controller, boolean isEnabled) {
		super("Remove All Highlights", owner);
		this.panel =  controller.getDecompilerPanel();
		this.controller = controller;

		setPopupMenuData(new MenuData(new String[] { "Remove All Highlights" }, "Decompile"));
		setHelpLocation(new HelpLocation(HelpTopics.SELECTION, getName()));
		
		setEnabled(isEnabled);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DecompilerActionContext)) {
			return false;
		}

		Function function = controller.getFunction();
		if (function instanceof UndefinedFunction) {
			return false;
		}

		DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
		if (decompilerActionContext.isDecompiling()) {
			return false;
		}

		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (panel != null) {
			HighlightTokenObservableList<HighlightToken> highlightTokens = panel.getHighlightedTokens();
			highlightTokens.clear();
			panel.clearHighlights();
			panel.tokenHighlightsChanged();
		}
	}
}
