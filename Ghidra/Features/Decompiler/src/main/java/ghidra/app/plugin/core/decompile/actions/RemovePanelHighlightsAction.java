package ghidra.app.plugin.core.decompile.actions;

import java.util.Iterator;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.decompiler.ClangFunction;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.decompiler.component.HighlightToken;
import ghidra.app.decompiler.component.HighlightTokenObservableList;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.HelpLocation;
import ghidra.util.UndefinedFunction;

public class RemovePanelHighlightsAction extends DockingAction{

	private DecompilerPanel panel;
	private DecompilerController controller;

	public RemovePanelHighlightsAction(String owner, DecompilerController controller) {
		this(owner, controller, false);
	}

	public RemovePanelHighlightsAction(String owner, DecompilerController controller, boolean isEnabled) {
		super("Remove Highlights", owner);
		this.panel =  controller.getDecompilerPanel();
		this.controller = controller;

		setPopupMenuData(new MenuData(new String[] { "Remove Panel Highlights" }, "Decompile"));
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
			ClangToken tokenAtCursor = panel.getTokenAtCursor();
			removeTokensFromFunction(tokenAtCursor.getClangFunction());
			panel.clearHighlights();
			panel.tokenHighlightsChanged();
		}
	}

	private Function getFunctionFromToken(ClangToken token) {
		if (token == null) {
			return null;
		}
		ClangFunction curClangFunction = token.getClangFunction();
		if (curClangFunction == null) {
			return null;
		}
		HighFunction curHighFunc = curClangFunction.getHighFunction();
		if (curHighFunc == null) {
			return null;
		}
		return curHighFunc.getFunction();
	}

	private void removeTokensFromFunction(ClangFunction function) {
		if (panel != null && function != null) {
			HighlightTokenObservableList<HighlightToken> highlightTokens = panel.getHighlightedTokens();
			ClangToken curToken = panel.getTokenAtCursor();
			
			Function curFunction = getFunctionFromToken(curToken);
			
			if (curFunction == null) {
				return;
			}
			
			Iterator<HighlightToken> it = highlightTokens.iterator();

			while (it.hasNext()) {
				HighlightToken tok = it.next();
				Function iterFunction = getFunctionFromToken(tok.getToken());
				if (iterFunction.equals(curFunction)) {
					it.remove();
				}
			}
			
			highlightTokens.notifyListeners();
			
		}
	}

}
