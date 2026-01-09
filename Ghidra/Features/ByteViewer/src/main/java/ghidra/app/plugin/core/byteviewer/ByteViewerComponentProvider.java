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
package ghidra.app.plugin.core.byteviewer;

import static ghidra.GhidraOptions.*;

import java.awt.Font;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.math.BigInteger;
import java.util.*;

import javax.swing.JComponent;
import javax.swing.KeyStroke;

import docking.*;
import docking.action.*;
import docking.action.builder.ActionBuilder;
import docking.action.builder.ToggleActionBuilder;
import docking.actions.PopupActionProvider;
import docking.widgets.fieldpanel.support.ViewerPosition;
import generic.theme.*;
import ghidra.GhidraOptions;
import ghidra.GhidraOptions.CURSOR_MOUSE_BUTTON_NAMES;
import ghidra.app.plugin.core.format.*;
import ghidra.app.services.MarkerService;
import ghidra.app.util.viewer.listingpanel.AddressSetDisplayListener;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.charset.CharsetInfo;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.SwingUpdateManager;

public abstract class ByteViewerComponentProvider extends ComponentProviderAdapter
		implements OptionsChangeListener, PopupActionProvider {

	protected static final String BLOCK_NUM = "Block Num";
	protected static final String BLOCK_OFFSET = "Block Offset";
	protected static final String BLOCK_COLUMN = "Block Column";
	protected static final String INDEX = "Index";
	protected static final String X_OFFSET = "X Offset";
	protected static final String Y_OFFSET = "Y Offset";
	private static final String VIEW_NAMES = "View Names";
	private static final String VIEW_WIDTHS = "View_Widths";
	static final int DEFAULT_NUMBER_OF_CHARS = 8;

	static final String DEFAULT_FONT_ID = "font.byteviewer";
	static final Font DEFAULT_FONT = Gui.getFont(DEFAULT_FONT_ID);
	static final String HEADER_FONT_ID = "font.byteviewer.header";
	static final Font HEADER_FONT = Gui.getFont(HEADER_FONT_ID);

	//@formatter:off
	static final GColor FG_COLOR = new GColor("color.fg");
	static final GColor BG_COLOR = new GColor("color.bg.byteviewer");
	static final GColor SEPARATOR_COLOR = new GColor("color.fg.byteviewer.separator");
	
	static final GColor EDITED_TEXT_COLOR = new GColor("color.fg.byteviewer.changed");
	static final GColor CURSOR_COLOR_FOCUSED_EDIT = new GColor("color.cursor.byteviewer.focused.edit");
	static final GColor CURSOR_COLOR_UNFOCUSED_EDIT = new GColor("color.cursor.byteviewer.unfocused.edit");
	static final GColor CURSOR_COLOR_FOCUSED_NON_EDIT = new GColor("color.cursor.byteviewer.focused.non.edit");
	static final GColor CURSOR_COLOR_UNFOCUSED_NON_EDIT = new GColor("color.cursor.byteviewer.unfocused.non.edit");

	static final GColor CURRENT_LINE_COLOR = GhidraOptions.DEFAULT_CURSOR_LINE_COLOR;
	static final GColor HIGHLIGHT_COLOR = new GColor("color.bg.byteviewer.highlight");
	static final GColor HIGHLIGHT_MIDDLE_MOUSE_COLOR = new GColor("color.bg.byteviewer.highlight.middle.mouse");
	//@formatter:on

	static final String INDEX_COLUMN_NAME = "Addresses";

	static final String SEPARATOR_COLOR_OPTION_NAME = "Block Separator Color";
	static final String EDIT_TEXT_COLOR_OPTION_NAME = "Edited Text Color";
	static final String CURSOR_FOCUSED_COLOR_OPTION_NAME = "Cursor Color Focused";
	static final String CURSOR_UNFOCUSED_COLOR_OPTION_NAME = "Cursor Color Unfocused";
	static final String CURSOR_FOCUSED_EDIT_COLOR_OPTION_NAME = "Cursor Color Focused Edit";
	static final String CURSOR_UNFOCUSED_EDIT_COLOR_OPTION_NAME = "Cursor Color Unfocused Edit";

	static final String OPTION_FONT = "Font";

	private static final String DEFAULT_VIEW = "Hex";
	private static final String OPTION_HIGHLIGHT_CURSOR_LINE =
		GhidraOptions.HIGHLIGHT_CURSOR_LINE_OPTION_NAME;
	private static final String OPTION_HIGHLIGHT_MIDDLE_MOUSE_NAME = "Middle Mouse Color";

	protected ByteViewerPanel panel;

	private ByteViewerConfigOptions configOptions = new ByteViewerConfigOptions();

	protected Map<String, ByteViewerComponent> viewMap = new HashMap<>();

	protected ToggleDockingAction editModeAction;

	protected ProgramByteBlockSet blockSet;

	protected final AbstractByteViewerPlugin<?> plugin;

	protected SwingUpdateManager updateManager;

	private Map<String, Class<? extends DataFormatModel>> dataFormatModelClassMap;
	private DockingAction shiftLeftAction;
	private DockingAction shiftRightAction;
	private DockingAction optionsAction;

	protected ByteViewerComponentProvider(PluginTool tool, AbstractByteViewerPlugin<?> plugin,
			String name, Class<?> contextType) {
		super(tool, name, plugin.getName(), contextType);
		this.plugin = plugin;
		registerAdjustableFontId(DEFAULT_FONT_ID);

		initializedDataFormatModelClassMap();

		panel = newByteViewerPanel();
		setIcon(new GIcon("icon.plugin.byteviewer.provider"));

		setOptions();

		createActions();

		updateManager = new SwingUpdateManager(1000, 3000, () -> refreshView());

		addView(DEFAULT_VIEW);
		setWindowMenuGroup("Byte Viewer");
		tool.addPopupActionProvider(this);
	}

	protected ByteViewerPanel newByteViewerPanel() {
		return new ByteViewerPanel(this);
	}

	private void initializedDataFormatModelClassMap() {
		dataFormatModelClassMap = new HashMap<>();
		Set<? extends DataFormatModel> models = getDataFormatModels();
		for (DataFormatModel model : models) {
			dataFormatModelClassMap.put(model.getName(), model.getClass());
		}
	}

	ToggleDockingAction getEditModeAction() {
		// for junit
		return editModeAction;
	}

	DockingAction getShiftLeftAction() {
		// for junit
		return shiftLeftAction;
	}

	DockingAction getShiftRightAction() {
		// for junit
		return shiftRightAction;
	}

	DockingAction getOptionsAction() {
		// for junit
		return optionsAction;
	}

	private void createActions() {
		editModeAction =
			new ToggleActionBuilder("Enable/Disable Byteviewer Editing", plugin.getName())
					.selected(false)
					.description("Enable/Disable editing of bytes in Byte Viewer panels.")
					.toolBarIcon(new GIcon("icon.base.edit.bytes"))
					.toolBarGroup("Byteviewer")
					.keyBinding(KeyStroke.getKeyStroke(KeyEvent.VK_E,
						DockingUtils.CONTROL_KEY_MODIFIER_MASK | InputEvent.ALT_DOWN_MASK))
					.enabledWhen(ac -> blockSet != null && blockSet.isValid())
					.onAction(ac -> setEditMode(editModeAction.isSelected()))
					.buildAndInstallLocal(this);

		optionsAction = new ActionBuilder("Byte Viewer Options", plugin.getName())
				.description("Set Byte Viewer Options")
				.toolBarIcon(new GIcon("icon.plugin.byteviewer.options"))
				.toolBarGroup("ZSettings")
				.enabledWhen(ac -> blockSet != null && blockSet.isValid())
				.onAction(ac -> tool.showDialog(
					new ByteViewerOptionsDialog(ByteViewerComponentProvider.this),
					ByteViewerComponentProvider.this))
				.buildAndInstallLocal(this);

		shiftLeftAction = new ActionBuilder("Shift Alignment Offset Left", plugin.getName())
				.description("Shift Alignment Offset Left")
				.popupMenuGroup("ByteOffsetShift")
				.popupMenuPath("Shift Bytes Left")
				.keyBinding("ctrl-comma")
				.enabledWhen(ac -> blockSet != null && blockSet.isValid())
				.onAction(ac -> adjustOffset(-1))
				.buildAndInstallLocal(this);

		shiftRightAction = new ActionBuilder("Shift Alignment Offset Right", plugin.getName())
				.description("Shift Alignment Offset Right")
				.popupMenuGroup("ByteOffsetShift")
				.popupMenuPath("Shift Bytes Right")
				.keyBinding("ctrl-period")
				.enabledWhen(ac -> blockSet != null && blockSet.isValid())
				.onAction(ac -> adjustOffset(+1))
				.buildAndInstallLocal(this);
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool t, ActionContext context) {
		if (context instanceof ByteViewerActionContext bvContext &&
			bvContext.getComponentProvider() == this) {
			return bvContext.getActiveColumn().getPopupActions(t, bvContext);
		}
		return null;
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation("ByteViewerPlugin", "ByteViewerPlugin");
	}

	protected ByteBlock[] getByteBlocks() {
		return (blockSet == null) ? null : blockSet.getBlocks();
	}

	/**
	 * Notification that an option changed.
	 *
	 * @param options options object containing the property that changed
	 * @param optionName name of option that changed
	 * @param oldValue old value of the option
	 * @param newValue new value of the option
	 */
	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {

		if (options.getName().equals(CATEGORY_BROWSER_FIELDS)) {
			if (optionName.equals(CURSOR_HIGHLIGHT_BUTTON_NAME)) {
				CURSOR_MOUSE_BUTTON_NAMES mouseButton = (CURSOR_MOUSE_BUTTON_NAMES) newValue;
				panel.setHighlightButton(mouseButton.getMouseEventID());
			}
		}
		else if (options.getName().equals("ByteViewer")) {
			if (optionName.equals(OPTION_HIGHLIGHT_CURSOR_LINE)) {
				panel.setHighlightCurrentLineEnabled((Boolean) newValue);
			}
		}

	}

	// Options.getStringEnum() is deprecated
	private void setOptions() {
		ToolOptions opt = tool.getOptions("ByteViewer");
		HelpLocation help = new HelpLocation("ByteViewerPlugin", "Option");
		opt.setOptionsHelpLocation(help);

		opt.registerThemeColorBinding(SEPARATOR_COLOR_OPTION_NAME, SEPARATOR_COLOR.getId(), help,
			"Color used for separator shown between memory blocks.");

		opt.registerThemeColorBinding(EDIT_TEXT_COLOR_OPTION_NAME, EDITED_TEXT_COLOR.getId(),
			new HelpLocation("ByteViewerPlugin", "EditColor"),
			"Color of changed bytes when editing.");

		opt.registerThemeColorBinding(CURSOR_FOCUSED_COLOR_OPTION_NAME,
			CURSOR_COLOR_FOCUSED_NON_EDIT.getId(),
			help, "Color of cursor in the focused view.");

		opt.registerThemeColorBinding(CURSOR_UNFOCUSED_COLOR_OPTION_NAME,
			CURSOR_COLOR_UNFOCUSED_NON_EDIT.getId(), help,
			"Color of cursor in the unfocused views.");

		opt.registerThemeColorBinding(CURSOR_FOCUSED_EDIT_COLOR_OPTION_NAME,
			CURSOR_COLOR_FOCUSED_EDIT.getId(), help,
			"Color of the cursor in the focused view when editing.");

		opt.registerThemeColorBinding(CURSOR_UNFOCUSED_EDIT_COLOR_OPTION_NAME,
			CURSOR_COLOR_UNFOCUSED_EDIT.getId(), help,
			"Color of the cursor in the unfocused view when editing.");

		opt.registerThemeColorBinding(OPTION_HIGHLIGHT_MIDDLE_MOUSE_NAME,
			HIGHLIGHT_MIDDLE_MOUSE_COLOR.getId(), help, "The middle-mouse highlight color.");

		opt.registerThemeFontBinding(OPTION_FONT, DEFAULT_FONT_ID, help, "Font used in the views.");

		boolean highlightCurrentLine = true;
		opt.registerOption(OPTION_HIGHLIGHT_CURSOR_LINE, highlightCurrentLine, help,
			"Toggles highlighting background color of line containing the cursor.");
		panel.setHighlightCurrentLineEnabled(highlightCurrentLine);

		opt.addOptionsChangeListener(this);

		// cursor highlight options
		opt = tool.getOptions(CATEGORY_BROWSER_FIELDS);
		GhidraOptions.CURSOR_MOUSE_BUTTON_NAMES mouseButton = opt.getEnum(
			CURSOR_HIGHLIGHT_BUTTON_NAME, GhidraOptions.CURSOR_MOUSE_BUTTON_NAMES.MIDDLE);
		panel.setHighlightButton(mouseButton.getMouseEventID());

		opt.addOptionsChangeListener(this);
	}

	/**
	 * Set the display offset that is applied to bytes in each block.
	 * <p>
	 * Changing this adjusts which byte appears first on each line of the grid.
	 * 
	 * @param newOffset the new block offset (0..bytesPerLine-1)
	 */
	public void setOffset(int newOffset) {
		if (configOptions.calcNormalizedOffset(newOffset) != configOptions.getOffset()) {
			configOptions.setOffset(newOffset);
			ViewerPosition vp = panel.getViewerPosition();
			panel.updateLayoutConfigOptions(configOptions);
			tool.setConfigChanged(true);
			panel.setViewerPosition(vp);
		}
	}

	void adjustOffset(int delta) {
		setOffset(configOptions.getOffset() + delta);
	}

	ByteBlockInfo getCursorLocation() {
		return panel.getCursorLocation();
	}

	ByteBlockSet getByteBlockSet() {
		return blockSet;
	}

	public ByteViewerConfigOptions getConfigOptions() {
		return configOptions;
	}

	public void updateConfigOptions(ByteViewerConfigOptions newOptions, Set<String> selectedViews) {

		boolean changed = removeDeletedViews(selectedViews);
		if (!configOptions.areOptionsEqual(newOptions)) {
			changed = true;

			boolean layoutChanged = configOptions.areLayoutParamsChanged(newOptions);
			boolean widthsChanged = configOptions.areDislayWidthsChanged(newOptions);

			configOptions = newOptions;

			for (ByteViewerComponent bvc : viewMap.values()) {
				bvc.getDataModel().setByteViewerConfigOptions(configOptions);
				bvc.invalidateModelFields();
			}

			if (layoutChanged || widthsChanged) {
				panel.updateLayoutConfigOptions(configOptions);
			}
			if (widthsChanged) {
				panel.resetColumnsToDefaultWidths();
			}
			panel.invalidate();
			panel.validate();
			panel.repaint();
		}

		changed |= addNewViews(selectedViews);

		if (changed) {
			refreshView();
			tool.setConfigChanged(true);
		}
	}

	private boolean removeDeletedViews(Set<String> selectedViews) {
		if (selectedViews == null) {
			return false;
		}
		boolean changed = false;
		for (String viewName : getCurrentViews()) {
			if (!selectedViews.contains(viewName)) {
				removeView(viewName, true);
				changed = true;
			}
		}
		return changed;
	}

	private boolean addNewViews(Set<String> selectedViews) {
		if (selectedViews == null) {
			return false;
		}
		boolean changed = false;
		Set<String> currentViews = getCurrentViews();

		// add any missing views
		for (String viewName : selectedViews) {
			if (!currentViews.contains(viewName)) {
				addView(viewName);
				changed = true;
			}
		}
		return changed;
	}

	private void updateModelConfig(String modelName) {
		ByteViewerComponent bvc = viewMap.get(modelName);
		if (bvc != null) {
			bvc.getDataModel().setByteViewerConfigOptions(configOptions);
			bvc.invalidateModelFields();
			panel.repaint();
		}
	}

	public void setCharsetInfo(CharsetInfo newCSI) {
		CharsetInfo oldCSI = configOptions.getCharsetInfo();
		if (!oldCSI.equals(newCSI)) {
			configOptions.setCharsetInfo(newCSI);
			// we know only Chars format cares about this setting
			updateModelConfig(CharacterFormatModel.NAME);
			if (oldCSI.getAlignment() != newCSI.getAlignment()) {
				panel.resetColumnsToDefaultWidths();
			}
			tool.setConfigChanged(true);
		}
	}

	public void setCompactChars(boolean newCompactChars) {
		if (configOptions.isCompactChars() != newCompactChars) {
			configOptions.setCompactChars(newCompactChars);
			// we know only Chars format cares about this setting, and that it will change column width
			updateModelConfig(CharacterFormatModel.NAME);
			panel.resetColumnsToDefaultWidths();
			tool.setConfigChanged(true);
		}
	}

	protected void writeConfigState(SaveState saveState) {
		List<String> viewNames = panel.getViewNamesInDisplayOrder();
		saveState.putStrings(VIEW_NAMES, viewNames.toArray(new String[viewNames.size()]));
		configOptions.write(saveState);
		SaveState columnState = new SaveState(VIEW_WIDTHS);
		int indexWidth = panel.getViewWidth(INDEX_COLUMN_NAME);
		columnState.putInt(INDEX_COLUMN_NAME, indexWidth);
		for (String viewName : viewNames) {
			int width = panel.getViewWidth(viewName);
			columnState.putInt(viewName, width);
		}
		saveState.putSaveState(VIEW_WIDTHS, columnState);
	}

	protected void readConfigState(SaveState saveState) {
		configOptions.read(saveState);

		String[] names = saveState.getStrings(VIEW_NAMES, new String[0]);
		restoreViews(names, false);

		panel.restoreConfigState(configOptions);

		SaveState viewWidths = saveState.getSaveState(VIEW_WIDTHS);
		if (viewWidths != null) {
			String[] viewNames = viewWidths.getNames();
			for (String viewName : viewNames) {
				int width = viewWidths.getInt(viewName, 0);
				if (width > 0) {
					panel.setViewWidth(viewName, width);
				}
			}
		}
	}

	/**
	 * Restore the views.
	 */
	private void restoreViews(String[] viewNames, boolean updateViewPosition) {
		// clear existing views
		for (String viewName : List.copyOf(viewMap.keySet())) {
			removeView(viewName, false);
		}
		for (String viewName : viewNames) {
			DataFormatModel dataFormatModel = getDataFormatModel(viewName);
			if (dataFormatModel != null) {
				addView(dataFormatModel, false, updateViewPosition);
			}
		}
		if (viewMap.isEmpty()) {
			addView(DEFAULT_VIEW);
		}
	}

	void addView(String modelName) {
		DataFormatModel dataFormatModel = getDataFormatModel(modelName);
		if (dataFormatModel != null) {
			addView(dataFormatModel, false, true);
		}
	}

	private ByteViewerComponent addView(DataFormatModel model, boolean configChanged,
			boolean updateViewPosition) {

		model.setByteViewerConfigOptions(configOptions);

		String viewName = model.getName();
		ByteViewerComponent bvc = panel.addView(viewName, model, updateViewPosition);
		viewMap.put(viewName, bvc);
		if (configChanged) {
			tool.setConfigChanged(true);
		}

		return bvc;
	}

	void removeView(String viewName, boolean configChanged) {
		ByteViewerComponent bvc = viewMap.remove(viewName);
		if (bvc == null) {
			return;
		}

		panel.removeView(bvc);

		if (configChanged) {
			tool.setConfigChanged(true);
		}

	}

	protected abstract void updateLocation(ByteBlock block, BigInteger blockOffset, int column,
			boolean export);

	protected abstract void updateSelection(ByteBlockSelection selection);

	protected abstract void updateLiveSelection(ByteViewerComponent bvc,
			ByteBlockSelection selection);

	void dispose() {
		tool.removePopupActionProvider(this);
		updateManager.dispose();
		updateManager = null;

		panel.dispose();

		if (blockSet != null) {
			blockSet.dispose();
		}

		blockSet = null;
	}

	public Set<String> getCurrentViews() {
		return new HashSet<String>(panel.getViewNamesInDisplayOrder());
	}

	private void refreshView() {
		if (tool == null) {
			return;
		}

		if (tool.isVisible(this)) {
			panel.refreshView();
		}

	}

	protected ByteViewerPanel getByteViewerPanel() {
		return panel;
	}

	/**
	 * Set the status info on the tool.
	 *
	 * @param message non-html text to display
	 */
	void setStatusMessage(String message) {
		plugin.setStatusMessage(message);
	}

	void setEditMode(boolean isEditable) {
		panel.setEditMode(isEditable);
	}

	protected Set<DataFormatModel> getDataFormatModels() {
		Set<DataFormatModel> set = new HashSet<>();
		set.addAll(ClassSearcher.getInstances(UniversalDataFormatModel.class));
		return set;
	}

	public List<String> getDataFormatNames() {
		ArrayList<String> names = new ArrayList<>(dataFormatModelClassMap.keySet());
		// we should probably have this in a better order, but at least this is consistent for now
		Collections.sort(names);
		return names;
	}

	/**
	 * Factory, creates instances of DataFormatModel.
	 * 
	 * @param formatName name
	 * @return new instance of the requested DataFormatModel
	 */
	public DataFormatModel getDataFormatModel(String formatName) {
		Class<? extends DataFormatModel> classy = dataFormatModelClassMap.get(formatName);
		if (classy == null) {
			return null;
		}
		try {
			return classy.getConstructor().newInstance();
		}
		catch (Exception e) {
			// cannot happen, since we only get the value from valid class that we put into the map
			Msg.error(this, "Unexpected error loading ByteViewer model formats", e);
		}
		return null;
	}

	public MarkerService getMarkerService() {
		return tool.getService(MarkerService.class);
	}

	/**
	 * Add the {@link AddressSetDisplayListener} to the byte viewer panel
	 *
	 * @param listener the listener to add
	 */
	public void addDisplayListener(AddressSetDisplayListener listener) {
		panel.addDisplayListener(listener);
	}

	/**
	 * Remove the {@link AddressSetDisplayListener} from the byte viewer panel
	 *
	 * @param listener the listener to remove
	 */
	public void removeDisplayListener(AddressSetDisplayListener listener) {
		panel.removeDisplayListener(listener);
	}

}
