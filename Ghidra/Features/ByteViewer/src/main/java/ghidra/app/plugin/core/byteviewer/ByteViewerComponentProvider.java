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

import java.awt.*;
import java.math.BigInteger;
import java.util.*;
import java.util.List;

import javax.swing.JComponent;

import ghidra.GhidraOptions;
import ghidra.GhidraOptions.CURSOR_MOUSE_BUTTON_NAMES;
import ghidra.app.plugin.core.format.*;
import ghidra.app.services.MarkerService;
import ghidra.app.util.viewer.listingpanel.AddressSetDisplayListener;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.*;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.SwingUpdateManager;
import resources.ResourceManager;

public abstract class ByteViewerComponentProvider extends ComponentProviderAdapter
		implements OptionsChangeListener {

	protected static final String BLOCK_NUM = "Block Num";
	protected static final String BLOCK_OFFSET = "Block Offset";
	protected static final String BLOCK_COLUMN = "Block Column";
	protected static final String INDEX = "Index";
	protected static final String X_OFFSET = "X Offset";
	protected static final String Y_OFFSET = "Y Offset";
	private static final String VIEW_NAMES = "View Names";
	private static final String HEX_VIEW_GROUPSIZE = "Hex view groupsize";
	private static final String BYTES_PER_LINE_NAME = "Bytes Per Line";
	private static final String OFFSET_NAME = "Offset";
	static final int DEFAULT_NUMBER_OF_CHARS = 8;

	static final Font DEFAULT_FONT = new Font("Monospaced", Font.PLAIN, 12);
	static final int DEFAULT_BYTES_PER_LINE = 16;
	static final Color DEFAULT_MISSING_VALUE_COLOR = Color.blue;
	static final Color DEFAULT_EDIT_COLOR = Color.red;
	static final Color DEFAULT_CURRENT_CURSOR_COLOR = Color.magenta.brighter();
	static final Color DEFAULT_CURSOR_COLOR = Color.black;
	static final Color DEFAULT_NONFOCUS_CURSOR_COLOR = Color.darkGray;
	private static final Color DEFAULT_CURSOR_LINE_COLOR = GhidraOptions.DEFAULT_CURSOR_LINE_COLOR;

	static final String DEFAULT_INDEX_NAME = "Addresses";

	static final String OPTION_EDIT_COLOR = "Edit Cursor Color";
	static final String OPTION_SEPARATOR_COLOR = "Block Separator Color";
	static final String OPTION_CURRENT_VIEW_CURSOR_COLOR = "Current View Cursor Color";
	static final String OPTION_CURSOR_COLOR = "Cursor Color";
	static final String OPTION_FONT = "Font";
	static final String OPTION_NONFOCUS_CURSOR_COLOR = "Non-Focus Cursor Color";

	private static final String DEFAULT_VIEW = "Hex";
	private static final String OPTION_CURRENT_LINE_COLOR =
		GhidraOptions.HIGHLIGHT_CURSOR_LINE_COLOR_OPTION_NAME;
	private static final String OPTION_HIGHLIGHT_CURSOR_LINE =
		GhidraOptions.HIGHLIGHT_CURSOR_LINE_OPTION_NAME;

	protected ByteViewerPanel panel;

	private Color editColor;
	private Color currentCursorColor;
	private Color defaultCursorColor;

	private int bytesPerLine;
	private int offset;
	private int hexGroupSize = 1;

	protected Map<String, ByteViewerComponent> viewMap = new HashMap<>();

	protected ToggleEditAction editModeAction;
	protected OptionsAction setOptionsAction;

	protected ProgramByteBlockSet blockSet;

	protected final AbstractByteViewerPlugin<?> plugin;

	protected SwingUpdateManager updateManager;

	private Map<String, Class<? extends DataFormatModel>> dataFormatModelClassMap;

	protected ByteViewerComponentProvider(PluginTool tool, AbstractByteViewerPlugin<?> plugin,
			String name,
			Class<?> contextType) {
		super(tool, name, plugin.getName(), contextType);
		this.plugin = plugin;

		initializedDataFormatModelClassMap();

		panel = newByteViewerPanel();
		bytesPerLine = DEFAULT_BYTES_PER_LINE;
		setIcon(ResourceManager.loadImage("images/binaryData.gif"));
		setOptions();

		createActions();

		updateManager = new SwingUpdateManager(1000, 3000, () -> refreshView());

		addView(DEFAULT_VIEW);
		setWindowMenuGroup("Byte Viewer");
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

	private void createActions() {
		editModeAction = new ToggleEditAction(this, plugin);
		setOptionsAction = new OptionsAction(this, plugin);

		addLocalAction(editModeAction);
		addLocalAction(setOptionsAction);
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
	 * @param group
	 * @param optionName name of option that changed
	 * @param oldValue old value of the option
	 * @param newValue new value of the option
	 */
	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		if (options.getName().equals("ByteViewer")) {

			if (optionName.equals(OPTION_CURRENT_VIEW_CURSOR_COLOR)) {
				panel.setCurrentCursorColor((Color) newValue);
			}
			else if (optionName.equals(OPTION_CURSOR_COLOR)) {
				panel.setCursorColor((Color) newValue);
			}
			else if (optionName.equals(OPTION_CURRENT_LINE_COLOR)) {
				panel.setCurrentCursorLineColor((Color) newValue);
			}
			else if (optionName.equals(OPTION_EDIT_COLOR)) {
				panel.setEditColor((Color) newValue);
			}
			else if (optionName.equals(OPTION_SEPARATOR_COLOR)) {
				panel.setSeparatorColor((Color) newValue);
			}
			else if (optionName.equals(OPTION_NONFOCUS_CURSOR_COLOR)) {
				panel.setNonFocusCursorColor((Color) newValue);
			}
			else if (optionName.equals(OPTION_FONT)) {
				setFont(SystemUtilities.adjustForFontSizeOverride((Font) newValue));
			}
		}
		else if (options.getName().equals(CATEGORY_BROWSER_FIELDS)) {
			if (optionName.equals(CURSOR_HIGHLIGHT_BUTTON_NAME)) {
				CURSOR_MOUSE_BUTTON_NAMES mouseButton = (CURSOR_MOUSE_BUTTON_NAMES) newValue;
				panel.setHighlightButton(mouseButton.getMouseEventID());
			}
			else if (optionName.equals(HIGHLIGHT_COLOR_NAME)) {
				panel.setMouseButtonHighlightColor((Color) newValue);
			}
		}
	}

	private void setFont(Font font) {
		FontMetrics fm = panel.getFontMetrics(font);
		panel.setFontMetrics(fm);
		tool.setConfigChanged(true);
	}

	// Options.getStringEnum() is deprecated
	private void setOptions() {
		ToolOptions opt = tool.getOptions("ByteViewer");
		HelpLocation help = new HelpLocation("ByteViewerPlugin", "Option");
		opt.setOptionsHelpLocation(help);

		opt.registerOption(OPTION_SEPARATOR_COLOR, DEFAULT_MISSING_VALUE_COLOR, help,
			"Color used for separator shown between memory blocks.");
		opt.registerOption(OPTION_SEPARATOR_COLOR, DEFAULT_MISSING_VALUE_COLOR, help,
			"Color used for separator shown between memory blocks.");
		opt.registerOption(OPTION_EDIT_COLOR, DEFAULT_EDIT_COLOR,
			new HelpLocation("ByteViewerPlugin", "EditColor"),
			"Color of cursor when the current view is in edit mode and can support editing.");
		opt.registerOption(OPTION_CURRENT_VIEW_CURSOR_COLOR, DEFAULT_CURRENT_CURSOR_COLOR, help,
			"Color of cursor when it is in the current view.");
		opt.registerOption(OPTION_NONFOCUS_CURSOR_COLOR, DEFAULT_NONFOCUS_CURSOR_COLOR, help,
			"Color of cursor when it is not the current view.");
		opt.registerOption(OPTION_CURSOR_COLOR, DEFAULT_CURSOR_COLOR, help,
			"Color of cursor for other views other than the current view.");
		opt.registerOption(OPTION_FONT, DEFAULT_FONT, help, "Font used in the views.");
		opt.registerOption(OPTION_CURRENT_LINE_COLOR, DEFAULT_CURSOR_LINE_COLOR, help,
			"Color of the line containing the cursor");
		opt.registerOption(OPTION_HIGHLIGHT_CURSOR_LINE, true, help,
			"Toggles highlighting background color of line containing the cursor");

		Color missingValueColor = opt.getColor(OPTION_SEPARATOR_COLOR, DEFAULT_MISSING_VALUE_COLOR);
		panel.setSeparatorColor(missingValueColor);

		editColor = opt.getColor(OPTION_EDIT_COLOR, DEFAULT_EDIT_COLOR);
		currentCursorColor =
			opt.getColor(OPTION_CURRENT_VIEW_CURSOR_COLOR, DEFAULT_CURRENT_CURSOR_COLOR);
		panel.setCurrentCursorColor(currentCursorColor);

		Color nonFocusCursorColor =
			opt.getColor(OPTION_NONFOCUS_CURSOR_COLOR, DEFAULT_NONFOCUS_CURSOR_COLOR);
		panel.setNonFocusCursorColor(nonFocusCursorColor);

		defaultCursorColor = opt.getColor(OPTION_CURSOR_COLOR, DEFAULT_CURSOR_COLOR);
		panel.setCursorColor(defaultCursorColor);

		Color cursorLineColor = opt.getColor(OPTION_CURRENT_LINE_COLOR, DEFAULT_CURSOR_LINE_COLOR);
		panel.setCurrentCursorLineColor(cursorLineColor);

		Font font =
			SystemUtilities.adjustForFontSizeOverride(opt.getFont(OPTION_FONT, DEFAULT_FONT));
		FontMetrics fm = panel.getFontMetrics(font);

		panel.restoreConfigState(fm, editColor);

		opt.addOptionsChangeListener(this);

		// cursor highlight options
		opt = tool.getOptions(CATEGORY_BROWSER_FIELDS);
		GhidraOptions.CURSOR_MOUSE_BUTTON_NAMES mouseButton = opt.getEnum(
			CURSOR_HIGHLIGHT_BUTTON_NAME, GhidraOptions.CURSOR_MOUSE_BUTTON_NAMES.MIDDLE);
		panel.setHighlightButton(mouseButton.getMouseEventID());

		panel.setMouseButtonHighlightColor(opt.getColor(HIGHLIGHT_COLOR_NAME, Color.YELLOW));

		opt.addOptionsChangeListener(this);
	}

	/**
	 * Set the offset that is applied to each block.
	 */
	void setBlockOffset(int blockOffset) {
		if (blockOffset == offset) {
			return;
		}
		int newOffset = blockOffset;
		if (newOffset > bytesPerLine) {
			newOffset = newOffset % bytesPerLine;
		}
		this.offset = newOffset;
		panel.setOffset(newOffset);
		tool.setConfigChanged(true);
	}

	ByteBlockInfo getCursorLocation() {
		return panel.getCursorLocation();
	}

	ByteBlockSelection getBlockSelection() {
		return panel.getViewerSelection();
	}

	void setBlockSelection(ByteBlockSelection selection) {
		panel.setViewerSelection(selection);
	}

	ByteBlockSet getByteBlockSet() {
		return blockSet;
	}

	/**
	 * Get the number of bytes displayed in a line.
	 */
	int getBytesPerLine() {
		return bytesPerLine;
	}

	/**
	 * Get the offset that should be applied to each byte block.
	 */
	int getOffset() {
		return offset;
	}

	Color getCursorColor() {
		return defaultCursorColor;
	}

	int getGroupSize() {
		return hexGroupSize;
	}

	void setGroupSize(int groupSize) {
		if (groupSize == hexGroupSize) {
			return;
		}
		hexGroupSize = groupSize;
		ByteViewerComponent component = viewMap.get(HexFormatModel.NAME);
		if (component != null) {
			component.setGroupSize(groupSize);
			component.invalidate();
			panel.repaint();
		}
		tool.setConfigChanged(true);
	}

	void setBytesPerLine(int bytesPerLine) {
		if (this.bytesPerLine != bytesPerLine) {
			this.bytesPerLine = bytesPerLine;
			panel.setBytesPerLine(bytesPerLine);
			tool.setConfigChanged(true);
		}
	}

	protected void writeConfigState(SaveState saveState) {
		DataModelInfo info = panel.getDataModelInfo();
		saveState.putStrings(VIEW_NAMES, info.getNames());
		saveState.putInt(HEX_VIEW_GROUPSIZE, hexGroupSize);
		saveState.putInt(BYTES_PER_LINE_NAME, bytesPerLine);
		saveState.putInt(OFFSET_NAME, offset);
	}

	protected void readConfigState(SaveState saveState) {
		String[] names = saveState.getStrings(VIEW_NAMES, new String[0]);
		hexGroupSize = saveState.getInt(HEX_VIEW_GROUPSIZE, 1);
		restoreViews(names, false);
		bytesPerLine = saveState.getInt(BYTES_PER_LINE_NAME, DEFAULT_BYTES_PER_LINE);
		offset = saveState.getInt(OFFSET_NAME, 0);
		panel.restoreConfigState(bytesPerLine, offset);
	}

	/**
	 * Restore the views.
	 */
	private void restoreViews(String[] viewNames, boolean updateViewPosition) {
		// clear existing views
		for (String viewName : viewMap.keySet()) {
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

		if (model.getName().equals(HexFormatModel.NAME)) {
			model.setGroupSize(hexGroupSize);
		}

		String viewName = model.getName();
		ByteViewerComponent bvc =
			panel.addView(viewName, model, editModeAction.isSelected(), updateViewPosition);
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

	void dispose() {
		updateManager.dispose();
		updateManager = null;

		if (blockSet != null) {
			blockSet.dispose();
		}

		blockSet = null;
	}

	public Set<String> getCurrentViews() {
		DataModelInfo info = panel.getDataModelInfo();
		HashSet<String> currentViewNames = new HashSet<>(Arrays.asList(info.getNames()));
		return currentViewNames;
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
