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
package ghidra.features.bsim.gui.structs;

import static ghidra.framework.main.DataTreeDialogType.*;

import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;

import db.Transaction;
import docking.DockingWindowManager;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.builder.ActionBuilder;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.*;
import ghidra.app.merge.structures.StructureMergeDialog;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ConsoleService;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFileFilter;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.*;
import ghidra.util.bean.opteditor.OptionsVetoException;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Plugin for recovering structure layouts across programs.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "StructureRecovery",
	description = "Plugin for recovering structure layouts across programs",
	servicesRequired = {
		ConsoleService.class
	},
	eventsConsumed = {
		ProgramActivatedPluginEvent.class, ProgramOpenedPluginEvent.class,
		ProgramLocationPluginEvent.class, ProgramSelectionPluginEvent.class,
		ProgramClosedPluginEvent.class
	})
//@formatter:on

public class StructureRecoveryPlugin extends ProgramPlugin implements OptionsChangeListener {

	static final String TAG_STRUCTURE_USE = "Tag structure use";
	static final String MATCH_FUNCTIONS = "Match functions";
	static final String REGENERATE_STRUCT = "Generate structure";
	static final String COMPARE_STRUCTURES = "Compare new structure";

	private static final String FUNCTIONS_MAP_BKMKS = "Function matches: map to bookmarks";
	private static final String FUNCTIONS_BKMKS_MAP = "Function matches: bookmarks to map";
	private static final String FUNCTIONS_BKMKS_DEL = "Function matches: remove bookmarks";
	private static final String USES_MAP_BKMKS = "Structure uses: map to bookmarks";
	private static final String USES_BKMKS_MAP = "Structure uses: bookmarks to map";
	private static final String USES_BKMKS_DEL = "Structure uses: remove bookmarks";

	public final static String HELP_LOCATION = "StructureRecovery";

	private static final String DEFAULT_STRUCTURE = "Structure to recover";
	private static final String ADD_STRUCTURE_USE_BKMKS = "Add structure-use bookmarks";
	private static final String ADD_FUNCTION_MATCH_BKMKS = "Add function-match bookmarks";
	private static final String SELF_SIGNIFICANCE_BOUND = "Self-significance bound";
	private static final String MATCH_SIMILARITY_LOWER_BOUND = "Match-similarity lower bound";
	private static final String MATCH_SIMILARITY_UPPER_BOUND = "Match-similarity upper bound";
	private static final String MATCH_CONFIDENCE_LOWER_BOUND = "Match-confidence lower bound";
	private static final String MIN_CONFIDENCE = "Min confidence";
	private static final String MAX_OFFSET = "Max structure offset";
	private static final String EXCLUDED_OFFSETS = "Excluded offsets (CSV hex values)";
	private static final String MATCH_ON = "Match on";

	public enum FunctionMatchOption {
		SOLO_MATCHES, SOLO_OR_MIN_CONFIDENCE, MAX_WEIGHT
	}

	Program targetProgram;

	Map<Function, Set<Function>> functionMap = new HashMap<>();
	Map<Function, Float> confidence = new HashMap<>();

	private Function currentFunction;
	private ConsoleService consoleService;

	private Structure targetDataType;
	private Map<String, Long> offsets = new HashMap<>();
	private Map<Long, String> names = new HashMap<>();
	private Set<Function> srcFunctionsToMatch = new HashSet<>();
	private Map<String, Set<Function>> srcFunctionsByField = new HashMap<>();
	private Map<String, AddressSet> srcAddressesByField = new HashMap<>();
	private ToolOptions options;
	private DockingAction tagAction;
	private DockingAction regenerateAction;
	private DockingAction compareAction;

	public StructureRecoveryPlugin(PluginTool tool) {
		super(tool);
		createActions();
		getOptions();
	}

	public Function getCurrentFunction() {
		return currentFunction;
	}

	@Override
	protected void programActivated(Program program) {
		currentProgram = program;
	}

	@Override
	protected void programClosed(Program program) {
		currentProgram = null;
	}

	private void createActions() {

		tagAction = new ActionBuilder(TAG_STRUCTURE_USE, HELP_LOCATION)
				.enabledWhen(_ -> getCurrentProgram() != null)
				.onAction(_ -> {
					if (checkDataType()) {
						tool.execute(new RetrieveUsesTask(StructureRecoveryPlugin.this));
					}
				})
				.menuGroup("A", "a")
				.menuPath("Tools", "Structure recovery", TAG_STRUCTURE_USE)
				.buildAndInstall(tool);

		new ActionBuilder(MATCH_FUNCTIONS, HELP_LOCATION)
				.enabledWhen(_ -> getCurrentProgram() != null && !srcFunctionsToMatch.isEmpty())
				.onAction(_ -> {
					tool.execute(
						new MatchFunctionsTask(StructureRecoveryPlugin.this, getTargetProgram()));
				})
				.menuGroup("A", "b")
				.menuPath("Tools", "Structure recovery", MATCH_FUNCTIONS)
				.buildAndInstall(tool);

		regenerateAction = new ActionBuilder(REGENERATE_STRUCT, HELP_LOCATION)
				.enabledWhen(_ -> getCurrentProgram() != null && !functionMap.isEmpty() &&
					targetProgram != currentProgram)
				.onAction(_ -> {
					if (checkDataType()) {
						tool.execute(new ComparePinningsTask(StructureRecoveryPlugin.this));
					}
				})
				.menuGroup("A", "c")
				.menuPath("Tools", "Structure recovery", REGENERATE_STRUCT)
				.buildAndInstall(tool);

		compareAction = new ActionBuilder(COMPARE_STRUCTURES, HELP_LOCATION)
				.enabledWhen(_ -> getCurrentProgram() != null)
				.onAction(_ -> {
					compareStructures();
				})
				.menuGroup("A", "d")
				.menuPath("Tools", "Structure recovery", COMPARE_STRUCTURES)
				.buildAndInstall(tool);

		new ActionBuilder(USES_BKMKS_MAP, HELP_LOCATION)
				.enabledWhen(_ -> getCurrentProgram() != null)
				.onAction(_ -> {
					if (checkDataType()) {
						getConsole().addMessage(USES_BKMKS_MAP, "Running...");
						regenerateUsesMapFromBookmarks();
						getConsole().addMessage(USES_BKMKS_MAP, "Finished!");
					}
				})
				.menuGroup("B", "a")
				.menuPath("Tools", "Structure recovery", USES_BKMKS_MAP)
				.buildAndInstall(tool);

		new ActionBuilder(USES_MAP_BKMKS, HELP_LOCATION)
				.enabledWhen(_ -> getCurrentProgram() != null && !srcFunctionsByField.isEmpty())
				.onAction(_ -> {
					getConsole().addMessage(USES_MAP_BKMKS, "Running...");
					generateUsesMapBookmarks();
					getConsole().addMessage(USES_MAP_BKMKS, "Finished!");
				})
				.menuGroup("B", "b")
				.menuPath("Tools", "Structure recovery", USES_MAP_BKMKS)
				.buildAndInstall(tool);

		new ActionBuilder(FUNCTIONS_BKMKS_MAP, HELP_LOCATION)
				.enabledWhen(_ -> getCurrentProgram() != null)
				.onAction(_ -> {
					getConsole().addMessage(FUNCTIONS_BKMKS_MAP, "Running...");
					regenerateFunctionMapFromBookmarks();
					getConsole().addMessage(FUNCTIONS_BKMKS_MAP, "Finished!");
				})
				.menuGroup("B", "c")
				.menuPath("Tools", "Structure recovery", FUNCTIONS_BKMKS_MAP)
				.buildAndInstall(tool);

		new ActionBuilder(FUNCTIONS_MAP_BKMKS, HELP_LOCATION)
				.enabledWhen(_ -> getCurrentProgram() != null && !functionMap.isEmpty())
				.onAction(_ -> {
					getConsole().addMessage(FUNCTIONS_MAP_BKMKS, "Running...");
					generateFunctionMapBookmarks();
					getConsole().addMessage(FUNCTIONS_MAP_BKMKS, "Finished!");
				})
				.menuGroup("B", "d")
				.menuPath("Tools", "Structure recovery", FUNCTIONS_MAP_BKMKS)
				.buildAndInstall(tool);

		new ActionBuilder(USES_BKMKS_DEL, HELP_LOCATION)
				.enabledWhen(_ -> getCurrentProgram() != null)
				.onAction(_ -> {
					wipeUsesMapBookmarks();
				})
				.menuGroup("B", "e")
				.menuPath("Tools", "Structure recovery", USES_BKMKS_DEL)
				.buildAndInstall(tool);

		new ActionBuilder(FUNCTIONS_BKMKS_DEL, HELP_LOCATION)
				.enabledWhen(_ -> getCurrentProgram() != null)
				.onAction(_ -> {
					wipeFunctionMapBookmarks();
				})
				.menuGroup("B", "f")
				.menuPath("Tools", "Structure recovery", FUNCTIONS_BKMKS_DEL)
				.buildAndInstall(tool);

	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) throws OptionsVetoException {
		if (optionName.equals(DEFAULT_STRUCTURE)) {
			checkDataType();
			boolean valid = targetDataType != null;
			String tagCmd = !valid ? TAG_STRUCTURE_USE : "Tag " + targetDataType.getName() + " use";
			String regenCmd = !valid ? REGENERATE_STRUCT
					: "Generate " + targetDataType.getName();
			if (targetProgram != null) {
				regenCmd += " (" + targetProgram + ")";
			}
			String compCmd = !valid ? COMPARE_STRUCTURES
					: "Compare " + targetDataType.getName() + " structures";
			tagAction.setMenuBarData(
				new MenuData(new String[] { "Tools", "Structure recovery", tagCmd }));
			regenerateAction.setMenuBarData(new MenuData(
				new String[] { "Tools", "Structure recovery", regenCmd }));
			compareAction.setMenuBarData(new MenuData(
				new String[] { "Tools", "Structure recovery", compCmd }));
		}
	}

	@Override
	public Program getCurrentProgram() {
		return currentProgram;
	}

	@Override
	public void close() {
		if (targetProgram != null) {
			targetProgram.release(this);
		}
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);

		//Msg.info(this, "TaintPlugin -> processEvent: " + event.toString() );

		if (event instanceof ProgramClosedPluginEvent) {
			if (currentProgram != null) {
				currentProgram.release(this);
			}
			return;
		}

		if (event instanceof ProgramActivatedPluginEvent) {
			currentProgram = ((ProgramActivatedPluginEvent) event).getActiveProgram();
		}
		else if (event instanceof ProgramLocationPluginEvent) {
			ProgramLocation location = ((ProgramLocationPluginEvent) event).getLocation();
			Address address = location.getAddress();

			if (address.isExternalAddress()) {
				// ignore external functions when it comes to taint.
				return;
			}

			if (currentProgram != null) {
				// The user loaded a program for analysis.
				Listing listing = currentProgram.getListing();
				Function f = listing.getFunctionContaining(address);
				// We are in function f
				if (currentFunction == null || !currentFunction.equals(f)) {
					currentFunction = f;
				}
			}
		}
	}

	private boolean checkDataType() {
		if (targetDataType != null) {
			return true;
		}
		if (currentProgram == null) {
			Msg.showWarn(this, null, "No Program",
				"Please open a program before selecting a structure.");
			return false;
		}
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		String structureName = getDefaultStructureName();
		DataType dataType = null;
		if (!structureName.equals("")) {
			dataType = dtm.getDataType(structureName);
			if (dataType == null) {
				List<DataType> list = new ArrayList<>();
				dtm.findDataTypes(structureName, list);
				if (list.isEmpty()) {
					Msg.error(this, dataType + " in ToolOptions is not valid.");
					return false;
				}
				dataType = list.get(0);
			}
		}
		else {
			DataTypeSelectionDialog selectionDialog =
				new DataTypeSelectionDialog(tool, dtm, -1, AllowedDataTypes.FIXED_LENGTH);
			tool.showDialog(selectionDialog);
			dataType = selectionDialog.getUserChosenDataType();
			if (dataType == null) {
				return false;
			}
			options.setString(DEFAULT_STRUCTURE, dataType.getPathName());
		}
		if (dataType instanceof Structure struct) {
			targetDataType = struct;
			offsets.clear();
			names.clear();
			for (DataTypeComponent dtc : targetDataType.getComponents()) {
				if (dtc.getFieldName() != null && dtc.getOffset() > 0) {
					offsets.put(dtc.getFieldName(), (long) dtc.getOffset());
					names.put((long) dtc.getOffset(), dtc.getFieldName());
				}
			}
			return true;
		}
		return false;
	}

	public Program loadTargetProgram() throws VersionException, IOException, CancelledException {
		DomainFileFilter filter = df -> Program.class.isAssignableFrom(df.getDomainObjectClass());
		DataTreeDialog dtd = new DataTreeDialog(null, "Target Program", OPEN, filter);
		dtd.show();
		if (dtd.wasCancelled()) {
			return null;
		}

		DomainFile df = dtd.getDomainFile();
		return (Program) df.getDomainObject(this, true, false, TaskMonitor.DUMMY);
	}

	private void generateFunctionMapBookmarks() {
		BookmarkManager srcBookmarks = currentProgram.getBookmarkManager();
		BookmarkManager tgtBookmarks = targetProgram.getBookmarkManager();
		try (Transaction _ = currentProgram.openTransaction("add")) {
			try (Transaction _ = targetProgram.openTransaction("add")) {
				for (Entry<Function, Set<Function>> entry : functionMap.entrySet()) {
					Function left = entry.getKey();
					for (Function right : entry.getValue()) {
						srcBookmarks.setBookmark(left.getEntryPoint(), MatchFunctionsTask.TAG,
							Long.toString(left.getID()), Long.toString(right.getID()));
						tgtBookmarks.setBookmark(right.getEntryPoint(), MatchFunctionsTask.TAG,
							Long.toString(left.getID()), Long.toString(right.getID()));
					}
				}
			}
		}
	}

	private void regenerateFunctionMapFromBookmarks() {
		getTargetProgram();
		FunctionManager srcMgr = currentProgram.getFunctionManager();
		FunctionManager tgtMgr = targetProgram.getFunctionManager();
		boolean adds = false;
		BookmarkManager bkmkMgr = currentProgram.getBookmarkManager();
		Iterator<Bookmark> iterator = bkmkMgr.getBookmarksIterator(MatchFunctionsTask.TAG);
		while (iterator.hasNext()) {
			Bookmark mark = iterator.next();
			try {
				Function left = srcMgr.getFunction(Long.parseLong(mark.getCategory()));
				if (left == null) {
					continue;
				}
				Set<Function> set = functionMap.computeIfAbsent(left, _ -> new HashSet<>());
				String tgtId = mark.getComment();
				Function right = tgtMgr.getFunction(Long.parseLong(tgtId));
				if (right == null) {
					continue;
				}
				set.add(right);
				adds = true;
			}
			catch (NumberFormatException e) {
				// Skip
			}
		}
		if (!adds) {
			getConsole().addErrorMessage(FUNCTIONS_BKMKS_MAP,
				"Map empty - check function id bookmarks");
		}
	}

	private void wipeFunctionMapBookmarks() {
		try (Transaction _ = currentProgram.openTransaction("wipeCurrent")) {
			getTargetProgram();
			BookmarkManager srcBookmarks = currentProgram.getBookmarkManager();
			srcBookmarks.removeBookmarks(MatchFunctionsTask.TAG);
		}
		getTargetProgram();
		try (Transaction _ = targetProgram.openTransaction("wipeTarget")) {
			getTargetProgram();
			BookmarkManager tgtBookmarks = targetProgram.getBookmarkManager();
			tgtBookmarks.removeBookmarks(MatchFunctionsTask.TAG);
		}
	}

	private void generateUsesMapBookmarks() {
		BookmarkManager bookmarkManager = currentProgram.getBookmarkManager();
		try (Transaction _ = currentProgram.openTransaction("add")) {
			for (Entry<String, Set<Function>> entry : srcFunctionsByField.entrySet()) {
				String fname = entry.getKey();
				AddressSet addressSet = srcAddressesByField.get(fname);
				if (addressSet == null) {
					continue;
				}
				Iterator<Function> iterator = entry.getValue().iterator();
				while (iterator.hasNext()) {
					Function f = iterator.next();
					AddressSet intersect = addressSet.intersect(f.getBody());
					if (intersect == null) {
						continue;
					}
					// Add a bookmark for each intersecting address range's minimum address so
					// it can be parsed back into a single address when rebuilding the map.
					for (AddressRange range : intersect.getAddressRanges()) {
						bookmarkManager.setBookmark(range.getMinAddress(), RetrieveUsesTask.TAG,
							"USES_" + targetDataType.getName(), fname);
					}
				}
			}
		}
	}

	private void regenerateUsesMapFromBookmarks() {
		FunctionManager srcMgr = currentProgram.getFunctionManager();
		BookmarkManager bkmkMgr = currentProgram.getBookmarkManager();
		Iterator<Bookmark> iterator = bkmkMgr.getBookmarksIterator(RetrieveUsesTask.TAG);
		while (iterator.hasNext()) {
			Bookmark mark = iterator.next();
			AddressSet aset =
				srcAddressesByField.computeIfAbsent(mark.getComment(), _ -> new AddressSet());
			Address address = mark.getAddress();
			if (address != null) {
				aset.add(address);
			}
			Set<Function> set =
				srcFunctionsByField.computeIfAbsent(mark.getComment(), _ -> new HashSet<>());
			Function f = srcMgr.getFunctionContaining(address);
			if (f != null) {
				set.add(f);
				srcFunctionsToMatch.add(f);
			}
		}
		if (srcFunctionsToMatch.isEmpty()) {
			getConsole().addErrorMessage(USES_BKMKS_MAP, "Map empty - check USES bookmarks");
		}
	}

	private void wipeUsesMapBookmarks() {
		try (Transaction _ = currentProgram.openTransaction("wipe")) {
			BookmarkManager bkmkMgr = currentProgram.getBookmarkManager();
			bkmkMgr.removeBookmarks(RetrieveUsesTask.TAG);
		}
	}

	private void compareStructures() {
		checkDataType();
		getTargetProgram();
		if (targetProgram == null) {
			consoleService.addErrorMessage("Compare Structures", "Target program is null.");
			return;
		}
		DataTypeManager dtm = targetProgram.getDataTypeManager();
		String structureName = "/RECOVERED_" + targetDataType.getName();
		DataType dataType = dtm.getDataType(structureName);
		if (dataType == null) {
			consoleService.addErrorMessage("Compare Structures", structureName + " not found.");
			return;
		}
		if (dataType instanceof Structure recoveredStructure) {
			StructureMergeDialog dialog =
				new StructureMergeDialog("Compare Structures", recoveredStructure, targetDataType,
					_ -> {
						//IGNORE
					});
			DockingWindowManager.showDialog(dialog);
		}
	}

	public Map<String, Long> getOffsets() {
		return offsets;
	}

	public Map<Long, String> getFieldNames() {
		return names;
	}

	public Map<Function, Set<Function>> getFunctionMap() {
		return functionMap;
	}

	public void setFunctionMap(Map<Function, Set<Function>> map) {
		this.functionMap = map;
	}

	public Map<String, Set<Function>> getFunctionsByField() {
		return srcFunctionsByField;
	}

	public void setFunctionsByField(Map<String, Set<Function>> functionsByField) {
		this.srcFunctionsByField = functionsByField;
	}

	public Map<String, AddressSet> getAddressesByField() {
		return srcAddressesByField;
	}

	public void setAddressesByField(Map<String, AddressSet> toAddressSet) {
		this.srcAddressesByField = toAddressSet;
	}

	public Set<Function> getFunctionsToMatch() {
		return srcFunctionsToMatch;
	}

	public void setFunctionsToMatch(Set<Function> srcFunctionsToMatch) {
		this.srcFunctionsToMatch = srcFunctionsToMatch;
	}

	public Structure getTargetDataType() {
		return targetDataType;
	}

	public ConsoleService getConsole() {
		if (consoleService == null) {
			consoleService = tool.getService(ConsoleService.class);
		}
		return consoleService;
	}

	public Program getTargetProgram() {
		if (targetProgram == null) {
			Swing.runNow(() -> {
				try {
					targetProgram = loadTargetProgram();
				}
				catch (VersionException | CancelledException | IOException e) {
					getConsole().addMessage("Load target", e.getMessage());
				}
			});
		}
		return targetProgram;
	}

	private void getOptions() {
		options = tool.getOptions("Structure Recovery");
		HelpLocation help = new HelpLocation(getName(), "Options");
		options.registerOption(DEFAULT_STRUCTURE, OptionType.STRING_TYPE, "", help,
			DEFAULT_STRUCTURE);
		options.registerOption(ADD_STRUCTURE_USE_BKMKS, OptionType.BOOLEAN_TYPE, true, help,
			"Generate structure-use function bookmarks by default");
		options.registerOption(ADD_FUNCTION_MATCH_BKMKS, OptionType.BOOLEAN_TYPE, true, help,
			"Generate function-match function bookmarks by default");
		options.registerOption(SELF_SIGNIFICANCE_BOUND, OptionType.DOUBLE_TYPE, 15.0, help,
			"Functions with self significance below this bound will be skipped");
		options.registerOption(MATCH_SIMILARITY_LOWER_BOUND, OptionType.DOUBLE_TYPE, 0.3, help,
			"Lower threshold equates to looser matches");
		options.registerOption(MATCH_SIMILARITY_UPPER_BOUND, OptionType.DOUBLE_TYPE, 1.0, help,
			"Decrease this if you only want to see matches that aren't exact");
		options.registerOption(MATCH_CONFIDENCE_LOWER_BOUND, OptionType.DOUBLE_TYPE, 0.0, help,
			MATCH_CONFIDENCE_LOWER_BOUND);
		options.registerOption(MIN_CONFIDENCE, OptionType.DOUBLE_TYPE, 20.0, help,
			"Consider matches above this confidence");
		options.registerOption(MAX_OFFSET, OptionType.LONG_TYPE, 100000L, help,
			"Ignore constants above this value as probable addresses");
		options.registerOption(EXCLUDED_OFFSETS, OptionType.STRING_TYPE, "", help,
			"Useful for structures using boxed randomized fields");
		options.registerOption(MATCH_ON, OptionType.ENUM_TYPE,
			FunctionMatchOption.SOLO_OR_MIN_CONFIDENCE, help,
			"Match using solo matches, solo+confidence, bipartite pairing");
		options.addOptionsChangeListener(this);
	}

	public String getDefaultStructureName() {
		return options.getString(DEFAULT_STRUCTURE, "");
	}

	public boolean getOptionStructUseBookmarks() {
		return options.getBoolean(ADD_STRUCTURE_USE_BKMKS, true);
	}

	public boolean getOptionFnMatchBookmarks() {
		return options.getBoolean(ADD_FUNCTION_MATCH_BKMKS, true);
	}

	public double getSelfSiginificanceBound() {
		return options.getDouble(SELF_SIGNIFICANCE_BOUND, 15.0);
	}

	public double getMatchSimilarityLowerBound() {
		return options.getDouble(MATCH_SIMILARITY_LOWER_BOUND, 0.3);
	}

	public double getMatchSimilarityUpperBound() {
		return options.getDouble(MATCH_SIMILARITY_UPPER_BOUND, 1.0);
	}

	public double getMatchConfidenceLowerBound() {
		return options.getDouble(MATCH_CONFIDENCE_LOWER_BOUND, 0.0);
	}

	public double getMinConfidence() {
		return options.getDouble(MIN_CONFIDENCE, 20.0);
	}

	public long getMaxOffset() {
		return options.getLong(MAX_OFFSET, 100000);
	}

	public Set<Long> getExcludedOffsets() {
		String offstr = options.getString(EXCLUDED_OFFSETS, "");
		String[] split = offstr.split(",");
		Set<Long> excluded = new HashSet<>();
		for (String offset : split) {
			if (!offset.equals("")) {
				try {
					excluded.add(Long.parseLong(offset.trim(), 16));
				}
				catch (NumberFormatException e) {
					// Skip
				}
			}
		}
		return excluded;
	}

	public FunctionMatchOption getOptionSoloMatchesOnly() {
		return options.getEnum(MATCH_ON, FunctionMatchOption.SOLO_OR_MIN_CONFIDENCE);
	}

}
