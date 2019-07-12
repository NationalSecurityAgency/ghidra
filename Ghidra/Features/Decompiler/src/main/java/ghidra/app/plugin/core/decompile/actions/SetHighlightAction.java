package ghidra.app.plugin.core.decompile.actions;

import java.awt.Color;
import java.awt.event.KeyEvent;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.decompiler.component.HighlightToken;
import ghidra.app.decompiler.component.HighlightTokenObservableList;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighVariable;
import ghidra.util.HelpLocation;
import ghidra.util.UndefinedFunction;

public class SetHighlightAction extends DockingAction {
	private DecompilerPanel panel;
	private DecompilerController controller;

	private int minColorSaturation = 100;
	private int defaultColorAlpha = 100;

	public SetHighlightAction(String owner, DecompilerController controller) {
		this(owner, controller, false);
	}

	/**
	 * Initialize the menu items, hotkeys and set the option to enabled according
	 * to the decompileOptions
	 */
	public SetHighlightAction(String owner, DecompilerController controller, boolean isEnabled) {
		super("Display.Custom Highlights", owner, false);
		this.panel =  controller.getDecompilerPanel();
		this.controller = controller;

		setPopupMenuData(new MenuData(new String[] { "Highlight Token" }, "Decompile"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_C, 0));
		setHelpLocation(new HelpLocation(HelpTopics.SELECTION, getName()));

		setEnabled(isEnabled);
	}

	/**
	 * Reset the highlighting accounting - This removes all highlighting.
	 */
	public void reset() {
		if (panel != null) {
			panel.getHighlightedTokens().clear();
			panel.tokenHighlightsChanged();
		}
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

		ClangToken tokenAtCursor = panel.getTokenAtCursor();
		if (tokenAtCursor == null) {
			return false;
		}

		HighVariable variable = tokenAtCursor.getHighVariable();
		tokenAtCursor.getSyntaxType();
		if (variable == null) {
			return false;
		}

		return true;
	}

	@Override
	public boolean setEnabled(boolean newValue) {

		if (newValue == false) {
			panel.repaintHighlightTokens(true);
		}

		return super.setEnabled(newValue);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (panel != null) {
			ClangToken tokenAtCursor = panel.getTokenAtCursor();

			HighlightTokenObservableList<HighlightToken> highlightTokens = panel.getHighlightedTokens();

			Function func = controller.getDecompileData().getFunction();

			Color highlightColor = getNewColor();
			HighlightToken htoken = new HighlightToken(tokenAtCursor, highlightColor, func);

			// If token was already highlighted (in the list), we remove it.
			if (highlightTokens.remove(htoken)) {
				panel.clearHighlights();
				panel.setHighlightedTokens(highlightTokens);
				panel.repaintHighlightTokens(true);
				panel.tokenHighlightsChanged();
			} else {
				// Token was not in the list, this is a new request to set highlighting
				highlightTokens.add(htoken);
				panel.setHighlightedTokens(highlightTokens);
				panel.addTokenHighlight(tokenAtCursor, highlightColor);
				panel.tokenHighlightsChanged();
			}
		}
	}

	private Color getNewColor() {
		return new Color((int)(minColorSaturation + Math.random() * (256 - minColorSaturation)),
				(int)(minColorSaturation + Math.random() * (256 - minColorSaturation)),
				(int)(minColorSaturation + Math.random() * (256 - minColorSaturation)), defaultColorAlpha);
	}

}
