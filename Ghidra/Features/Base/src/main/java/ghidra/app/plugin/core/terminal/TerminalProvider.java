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
package ghidra.app.plugin.core.terminal;

import java.awt.*;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.*;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import org.apache.commons.collections4.IteratorUtils;

import docking.*;
import docking.action.DockingAction;
import docking.action.DockingActionIf;
import docking.action.builder.ActionBuilder;
import docking.widgets.EventTrigger;
import docking.widgets.OkDialog;
import docking.widgets.fieldpanel.support.*;
import generic.theme.GColor;
import generic.theme.GIcon;
import ghidra.app.plugin.core.terminal.TerminalPanel.FindOptions;
import ghidra.app.plugin.core.terminal.vt.VtOutput;
import ghidra.app.services.ClipboardService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.Plugin;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;

/**
 * A window holding a VT100 terminal emulator.
 * 
 * <p>
 * This also provides UI actions for searching the terminal's contents.
 */
public class TerminalProvider extends ComponentProviderAdapter {
	// TODO: A separate color?
	private static final Color COLOR_TERMINATED = new GColor("color.border.provider.disconnected");

	protected class FindDialog extends DialogComponentProvider {
		protected final JTextField txtFind = new JTextField(20);
		protected final JCheckBox cbCaseSensitive = new JCheckBox("Case sensitive");
		protected final JCheckBox cbWrapSearch = new JCheckBox("Wrap search");
		protected final JCheckBox cbWholeWord = new JCheckBox("Whole word");
		protected final JCheckBox cbRegex = new JCheckBox("Regular expression");

		protected final JButton btnFindNext = new JButton("Next");
		protected final JButton btnFindPrevious = new JButton("Previous");

		protected FindDialog() {
			super("Find", false, false, true, false);

			populateComponents();
		}

		protected GridBagConstraints cell(int row, int col, int width, boolean hFill) {
			GridBagConstraints constraints = new GridBagConstraints();
			constraints.gridx = col;
			constraints.gridy = row;
			constraints.gridwidth = width;
			constraints.fill = GridBagConstraints.HORIZONTAL;
			constraints.insets = new Insets(row == 0 ? 0 : 5, col == 0 ? 0 : 3, 0, 0);
			constraints.weightx = hFill ? 1.0 : 0.0;
			return constraints;
		}

		protected JLabel label(String text) {
			JLabel label = new JLabel(text);
			label.setHorizontalAlignment(SwingConstants.RIGHT);
			return label;
		}

		protected void populateComponents() {
			JPanel panel = new JPanel(new GridBagLayout());
			panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

			panel.add(label("Find"), cell(0, 0, 1, false));
			panel.add(txtFind, cell(0, 1, 1, true));

			panel.add(cbCaseSensitive, cell(2, 0, 2, true));
			panel.add(cbWrapSearch, cell(3, 0, 2, true));
			panel.add(cbWholeWord, cell(4, 0, 2, true));
			panel.add(cbRegex, cell(5, 0, 2, true));

			addWorkPanel(panel);

			addButton(btnFindNext);
			addButton(btnFindPrevious);
			addDismissButton();
			setDefaultButton(btnFindNext);

			txtFind.getDocument().addDocumentListener(new DocumentListener() {
				@Override
				public void insertUpdate(DocumentEvent e) {
					contextChanged();
					btnFindNext.setEnabled(isEnabledFindStep(null));
					btnFindPrevious.setEnabled(isEnabledFindStep(null));
				}

				@Override
				public void removeUpdate(DocumentEvent e) {
					contextChanged();
					btnFindNext.setEnabled(isEnabledFindStep(null));
					btnFindPrevious.setEnabled(isEnabledFindStep(null));
				}

				@Override
				public void changedUpdate(DocumentEvent e) {
					contextChanged();
					btnFindNext.setEnabled(isEnabledFindStep(null));
					btnFindPrevious.setEnabled(isEnabledFindStep(null));
				}
			});
			btnFindNext.addActionListener(evt -> {
				activatedFindNext(null);
			});
			btnFindPrevious.addActionListener(evt -> {
				activatedFindPrevious(null);
			});
		}

		public Set<FindOptions> getOptions() {
			EnumSet<FindOptions> opts = EnumSet.noneOf(FindOptions.class);
			if (cbCaseSensitive.isSelected()) {
				opts.add(FindOptions.CASE_SENSITIVE);
			}
			if (cbWrapSearch.isSelected()) {
				opts.add(FindOptions.WRAP);
			}
			if (cbWholeWord.isSelected()) {
				opts.add(FindOptions.WHOLE_WORD);
			}
			if (cbRegex.isSelected()) {
				opts.add(FindOptions.REGEX);
			}
			return opts;
		}
	}

	protected final TerminalPlugin plugin;
	protected final Plugin helpPlugin;

	protected final TerminalPanel panel;
	protected final FindDialog findDialog = new FindDialog();

	protected DockingAction actionFind;
	protected DockingAction actionFindNext;
	protected DockingAction actionFindPrevious;
	protected DockingAction actionSelectAll;
	protected DockingAction actionTerminate;
	protected DockingAction actionIncreaseSize;
	protected DockingAction actionDecreaseSize;
	protected DockingAction actionResetSize;

	private boolean terminated = false;

	public TerminalProvider(TerminalPlugin plugin, Charset charset, Plugin helpPlugin) {
		super(plugin.getTool(), "Terminal", plugin.getName());
		this.plugin = plugin;
		this.helpPlugin = helpPlugin;
		this.panel = new TerminalPanel(charset, this);
		this.panel.addTerminalListener(new TerminalListener() {
			@Override
			public void retitled(String title) {
				setSubTitle(title);
			}
		});
		createActions();
		setWindowMenuGroup("Terminals");
		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setHelpLocation(new HelpLocation(helpPlugin.getName(), "plugin"));

		// Avoid change in dimension when "terminated" border is applied
		panel.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	public void processInput(ByteBuffer buffer) {
		panel.processInput(buffer);
	}

	public TerminalPanel getTerminalPanel() {
		return panel;
	}

	@Override
	public void removeFromTool() {
		panel.dispose();
		plugin.providers.remove(this);
		super.removeFromTool();
	}

	public void setOutputCallback(VtOutput outputCb) {
		panel.setOutputCallback(outputCb);
	}

	public void addTerminalListener(TerminalListener listener) {
		panel.addTerminalListener(listener);
	}

	public void removeTerminalListener(TerminalListener listener) {
		panel.removeTerminalListener(listener);
	}

	public void setClipboardService(ClipboardService clipboardService) {
		panel.setClipboardService(clipboardService);
	}

	protected void createActions() {
		actionFind = new ActionBuilder("Find", plugin.getName())
				.menuIcon(new GIcon("icon.search"))
				.menuPath("Find")
				.menuGroup("Find")
				.keyBinding(KeyStroke.getKeyStroke(KeyEvent.VK_F,
					InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK))
				.helpLocation(new HelpLocation(helpPlugin.getName(), "find"))
				.onAction(this::activatedFind)
				.buildAndInstallLocal(this);
		actionFindNext = new ActionBuilder("Find Next", plugin.getName())
				.menuPath("Find Next")
				.menuGroup("Find")
				.keyBinding(KeyStroke.getKeyStroke(KeyEvent.VK_H,
					InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK))
				.helpLocation(new HelpLocation(helpPlugin.getName(), "find_next"))
				.enabledWhen(this::isEnabledFindStep)
				.onAction(this::activatedFindNext)
				.buildAndInstallLocal(this);
		actionFindPrevious = new ActionBuilder("Find Previous", plugin.getName())
				.menuPath("Find Previous")
				.menuGroup("Find")
				.keyBinding(KeyStroke.getKeyStroke(KeyEvent.VK_G,
					InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK))
				.helpLocation(new HelpLocation(helpPlugin.getName(), "find_previous"))
				.enabledWhen(this::isEnabledFindStep)
				.onAction(this::activatedFindPrevious)
				.buildAndInstallLocal(this);
		actionSelectAll = new ActionBuilder("Select All", plugin.getName())
				.menuPath("Select All")
				.menuGroup("Select")
				.keyBinding(KeyStroke.getKeyStroke(KeyEvent.VK_A,
					InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK))
				.helpLocation(new HelpLocation(helpPlugin.getName(), "select_all"))
				.onAction(this::activatedSelectAll)
				.buildAndInstallLocal(this);
		actionIncreaseSize = new ActionBuilder("Increase Font Size", plugin.getName())
				.menuPath("Increase Font Size")
				.menuGroup("View")
				.keyBinding(KeyStroke.getKeyStroke(KeyEvent.VK_EQUALS,
					InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK))
				.helpLocation(new HelpLocation(helpPlugin.getName(), "increase_font_size"))
				.onAction(this::activatedIncreaseFontSize)
				.buildAndInstallLocal(this);
		actionDecreaseSize = new ActionBuilder("Decrease Font Size", plugin.getName())
				.menuPath("Decrease Font Size")
				.menuGroup("View")
				.keyBinding(KeyStroke.getKeyStroke(KeyEvent.VK_MINUS, InputEvent.CTRL_DOWN_MASK))
				.helpLocation(new HelpLocation(helpPlugin.getName(), "decrease_font_size"))
				.onAction(this::activatedDecreaseFontSize)
				.buildAndInstallLocal(this);
		actionResetSize = new ActionBuilder("Reset Font Size", plugin.getName())
				.menuPath("Reset Font Size")
				.menuGroup("View")
				.keyBinding(KeyStroke.getKeyStroke(KeyEvent.VK_0, InputEvent.CTRL_DOWN_MASK))
				.helpLocation(new HelpLocation(helpPlugin.getName(), "decrease_font_size"))
				.onAction(this::activatedResetFontSize)
				.buildAndInstallLocal(this);
	}

	protected void activatedFind(ActionContext ctx) {
		tool.showDialog(findDialog);
	}

	protected void doFind(boolean forward) {
		FieldSelection sel = panel.getFieldPanel().getSelection();
		final FieldLocation start;
		if (sel == null || sel.getNumRanges() == 0) {
			start = null;
		}
		else {
			FieldLocation s = sel.getFieldRange(0).getStart();
			if (forward) {
				start = new FieldLocation(s.getIndex(), 0, 0, s.getCol() + 1);
			}
			else {
				/**
				 * The search algorithm should work such that col == -1 works the same as the end of
				 * the previous line -- or no result if its the first line.
				 */
				start = new FieldLocation(s.getIndex(), 0, 0, s.getCol() - 1);
			}
		}
		FieldRange found =
			panel.find(findDialog.txtFind.getText(), findDialog.getOptions(), start, forward);
		if (found == null) {
			OkDialog.showInfo("Find", "String not found");
			return;
		}
		FieldSelection newSel = new FieldSelection();
		newSel.addRange(found);
		panel.fieldPanel.setSelection(newSel);
		panel.fieldPanel.scrollTo(found.getStart());
	}

	protected boolean isEnabledFindStep(ActionContext ctx) {
		return !findDialog.txtFind.getText().isEmpty();
	}

	protected void activatedFindNext(ActionContext ctx) {
		doFind(true);
	}

	protected void activatedFindPrevious(ActionContext ctx) {
		doFind(false);
	}

	protected void activatedSelectAll(ActionContext ctx) {
		FieldSelection sel = new FieldSelection();
		BigInteger numIndexes = panel.model.getNumIndexes();
		if (numIndexes.equals(BigInteger.ZERO)) {
			return;
		}
		BigInteger lastIndex = numIndexes.subtract(BigInteger.ONE);
		TerminalLayout layout = panel.model.getLayout(lastIndex);
		int lastCol = layout.line.length();
		sel.addRange(
			new FieldLocation(BigInteger.ZERO, 0, 0, 0),
			new FieldLocation(lastIndex, 0, 0, lastCol));
		if (panel.getFieldPanel().getSelection().equals(sel)) {
			sel.clear();
		}
		panel.getFieldPanel().setSelection(sel, EventTrigger.GUI_ACTION);
	}

	protected void activatedIncreaseFontSize(ActionContext ctx) {
		panel.increaseFontSize();
	}

	protected void activatedDecreaseFontSize(ActionContext ctx) {
		panel.decreaseFontSize();
	}

	protected void activatedResetFontSize(ActionContext ctx) {
		panel.resetFontSize();
	}

	/**
	 * Check if the given keystroke would activate a local action.
	 * 
	 * <p>
	 * Because we usurp control of the keyboard, but we still want local actions accessible via
	 * keyboard shortcuts, we need a way to check if a local action could take the stroke. In this
	 * way, we allow local actions to override the terminal, but not tool/global actions.
	 * 
	 * @param e the event
	 * @return true if a local action could be activated
	 */
	protected boolean isLocalActionKeyBinding(KeyEvent e) {
		KeyStroke stroke = KeyStroke.getKeyStrokeForEvent(e);
		DockingWindowManager wm = DockingWindowManager.getActiveInstance();
		for (DockingActionIf action : IteratorUtils.asIterable(wm.getComponentActions(this))) {
			if (Objects.equals(stroke, action.getKeyBinding())) {
				return true;
			}
		}
		return false;
	}

	public void setFixedSize(short cols, short rows) {
		panel.setFixedTerminalSize(cols, rows);
	}

	public void setDyanmicSize() {
		panel.setDynamicTerminalSize();
	}

	public int getColumns() {
		return panel.getColumns();
	}

	public int getRows() {
		return panel.getRows();
	}

	public void setMaxScrollBackRows(int rows) {
		panel.model.setMaxScrollBackSize(rows);
	}

	public int getScrollBackRows() {
		return panel.model.getScrollBackSize();
	}

	public String getRangeText(int startCol, int startLine, int endCol, int endLine) {
		int scrollBack = getScrollBackRows();
		return panel.getSelectedText(new FieldRange(
			new FieldLocation(startLine + scrollBack, 0, 0, startCol),
			new FieldLocation(endLine + scrollBack, 0, 0, endCol)));
	}

	public int getCursorColumn() {
		return panel.getCursorColumn();
	}

	public int getCursorRow() {
		return panel.getCursorRow();
	}

	/**
	 * Notify the provider that the terminal's session has terminated
	 * 
	 * <p>
	 * The title and sub title are adjusted and all terminal listeners are removed. If/when the
	 * window is closed, it is removed from the tool.
	 */
	public void terminated() {
		Swing.runIfSwingOrRunLater(() -> {
			terminated = true;
			removeLocalAction(actionTerminate);
			panel.terminalListeners.clear();
			panel.setOutputCallback(buf -> {
			});
			panel.getFieldPanel().setCursorOn(false);
			setTitle("[Terminal]");
			setSubTitle("Terminated");
			if (!isVisible()) {
				removeFromTool();
			}
			else {
				panel.setBorder(BorderFactory.createLineBorder(COLOR_TERMINATED, 2));
			}
		});
	}

	public boolean isTerminated() {
		return terminated;
	}

	public void setTerminateAction(Runnable action) {
		if (actionTerminate != null) {
			removeLocalAction(actionTerminate);
		}
		if (action != null) {
			actionTerminate = new ActionBuilder("Terminate", plugin.getName())
					.menuIcon(new GIcon("icon.plugin.terminal.terminate"))
					.menuPath("Terminate")
					.menuGroup("Terminate")
					.helpLocation(new HelpLocation(helpPlugin.getName(), "terminate"))
					.enabledWhen(ctx -> true)
					.onAction(ctx -> action.run())
					.buildAndInstallLocal(this);
		}
	}

	@Override
	public void closeComponent() {
		super.closeComponent();
		if (terminated) {
			removeFromTool();
		}
	}
}
