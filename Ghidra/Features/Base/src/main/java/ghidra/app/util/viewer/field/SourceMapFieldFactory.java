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
package ghidra.app.util.viewer.field;

import java.awt.Color;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.GhidraOptions;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.database.sourcemap.SourceFileIdType;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.sourcemap.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.SourceMapFieldLocation;
import ghidra.util.HelpLocation;

/**
 * {@link FieldFactory} for showing source and line information in the Listing.
 */
public class SourceMapFieldFactory extends FieldFactory {

	static final String FIELD_NAME = "Source Map";
	private static final String GROUP_TITLE = "Source Map";
	static final String SHOW_FILENAME_ONLY_OPTION_NAME =
		GROUP_TITLE + Options.DELIMITER + "Show Filename Only";
	static final String SHOW_INFO_AT_ALL_ADDRESSES_OPTION_NAME =
		GROUP_TITLE + Options.DELIMITER + "Show Source Info at Every Address";
	static final String MAX_ENTRIES_PER_ADDRESS_OPTION_NAME =
		GROUP_TITLE + Options.DELIMITER + "Maximum Number of Source Map Entries to Display";
	static final String SHOW_IDENTIFIER_OPTION_NAME =
		GROUP_TITLE + Options.DELIMITER + "Show Identifier";
	static final String NO_SOURCE_INFO = "unknown:??";

	private boolean showOnlyFileNames = true;
	private boolean showInfoAtAllAddresses = false;
	private boolean showIdentifier = false;
	private static final int DEFAULT_MAX_ENTRIES = 4;
	private int maxEntries = DEFAULT_MAX_ENTRIES;
	static Color OFFCUT_COLOR = Palette.GRAY;

	/**
	 * Default constructor
	 */
	public SourceMapFieldFactory() {
		super(FIELD_NAME);
	}

	protected SourceMapFieldFactory(FieldFormatModel model,
			ListingHighlightProvider highlightProvider, Options displayOptions,
			Options fieldOptions) {
		super(FIELD_NAME, model, highlightProvider, displayOptions, fieldOptions);
		registerOptions(fieldOptions);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel,
			ListingHighlightProvider highlightProvider, ToolOptions options,
			ToolOptions fieldOptions) {
		return new SourceMapFieldFactory(formatModel, highlightProvider, options, fieldOptions);
	}

	@Override
	public ListingField getField(ProxyObj<?> obj, int varWidth) {
		if (!enabled) {
			return null;
		}
		if (!(obj.getObject() instanceof CodeUnit cu)) {
			return null;
		}

		List<SourceMapEntry> entriesToShow = getSourceMapEntries(cu);
		if (entriesToShow.isEmpty()) {
			if (!showInfoAtAllAddresses) {
				return null;
			}
			AttributedString attrString =
				new AttributedString(NO_SOURCE_INFO, Palette.BLACK, getMetrics());
			return ListingTextField.createSingleLineTextField(this, obj,
				new TextFieldElement(attrString, 0, 0), startX + varWidth, width, hlProvider);
		}
		List<FieldElement> fieldElements = new ArrayList<>();

		Address cuAddr = cu.getAddress();
		if (!showInfoAtAllAddresses) {
			List<SourceMapEntry> entriesStartingWithinCu = new ArrayList<>();
			for (SourceMapEntry entry : entriesToShow) {
				if (entry.getBaseAddress().compareTo(cuAddr) >= 0) {
					entriesStartingWithinCu.add(entry);
				}
			}
			if (entriesStartingWithinCu.isEmpty()) {
				return null;
			}
			entriesToShow = entriesStartingWithinCu;
		}

		for (SourceMapEntry entry : entriesToShow) {
			StringBuilder sb = new StringBuilder();
			if (showOnlyFileNames) {
				sb.append(entry.getSourceFile().getFilename());
			}
			else {
				sb.append(entry.getSourceFile().getPath());
			}
			sb.append(":");
			sb.append(entry.getLineNumber());
			sb.append(" (");
			sb.append(entry.getLength());
			sb.append(")");
			if (showIdentifier) {
				SourceFile sourceFile = entry.getSourceFile();
				if (sourceFile.getIdType().equals(SourceFileIdType.NONE)) {
					sb.append(" [no id]");
				}
				else {
					sb.append(" [");
					sb.append(sourceFile.getIdType().name());
					sb.append("=");
					sb.append(sourceFile.getIdAsString());
					sb.append("]");
				}
			}
			// use gray for entries which start "within" the code unit
			Color color =
				entry.getBaseAddress().compareTo(cuAddr) <= 0 ? Palette.BLACK : OFFCUT_COLOR;
			AttributedString attrString = new AttributedString(sb.toString(), color, getMetrics());
			fieldElements.add(new TextFieldElement(attrString, 0, 0));
		}

		return ListingTextField.createMultilineTextField(this, obj, fieldElements,
			startX + varWidth, width, maxEntries, hlProvider);
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {
		if (loc instanceof SourceMapFieldLocation sourceField) {
			return new FieldLocation(index, fieldNum, sourceField.getRow(),
				sourceField.getCharOffset());
		}
		return null;
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		Object obj = bf.getProxy().getObject();
		if (!(obj instanceof CodeUnit cu)) {
			return null;
		}
		List<SourceMapEntry> entriesToShow = getSourceMapEntries(cu);
		if (entriesToShow == null || entriesToShow.size() <= row) {
			return null;
		}
		return new SourceMapFieldLocation(cu.getProgram(), cu.getAddress(), row, col,
			entriesToShow.get(row));
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		return (category == FieldFormatModel.INSTRUCTION_OR_DATA);
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		super.fieldOptionsChanged(options, optionName, oldValue, newValue);

		if (options.getName().equals(GhidraOptions.CATEGORY_BROWSER_FIELDS)) {
			if (optionName.equals(SHOW_FILENAME_ONLY_OPTION_NAME)) {
				showOnlyFileNames = options.getBoolean(SHOW_FILENAME_ONLY_OPTION_NAME, true);
			}
			if (optionName.equals(SHOW_INFO_AT_ALL_ADDRESSES_OPTION_NAME)) {
				showInfoAtAllAddresses =
					options.getBoolean(SHOW_INFO_AT_ALL_ADDRESSES_OPTION_NAME, false);
			}
			if (optionName.equals(MAX_ENTRIES_PER_ADDRESS_OPTION_NAME)) {
				maxEntries =
					options.getInt(MAX_ENTRIES_PER_ADDRESS_OPTION_NAME, DEFAULT_MAX_ENTRIES);
			}
			if (optionName.equals(SHOW_IDENTIFIER_OPTION_NAME)) {
				showIdentifier = options.getBoolean(SHOW_IDENTIFIER_OPTION_NAME, false);
			}
			model.update();
		}
	}

	private void registerOptions(Options fieldOptions) {
		HelpLocation helpLoc = new HelpLocation("CodeBrowserPlugin", "Source_Map_Field");

		fieldOptions.registerOption(SHOW_FILENAME_ONLY_OPTION_NAME, true, helpLoc,
			"Show only source file name (rather than absolute path)");
		showOnlyFileNames = fieldOptions.getBoolean(SHOW_FILENAME_ONLY_OPTION_NAME, true);

		fieldOptions.registerOption(SHOW_INFO_AT_ALL_ADDRESSES_OPTION_NAME, false, helpLoc,
			"Show source info at every address " +
				"(rather than only at beginning of source map entries)");
		showInfoAtAllAddresses =
			fieldOptions.getBoolean(SHOW_INFO_AT_ALL_ADDRESSES_OPTION_NAME, false);

		fieldOptions.registerOption(MAX_ENTRIES_PER_ADDRESS_OPTION_NAME, 4, helpLoc,
			"Maximum number of source map entries to display");
		maxEntries = fieldOptions.getInt(MAX_ENTRIES_PER_ADDRESS_OPTION_NAME, DEFAULT_MAX_ENTRIES);

		fieldOptions.registerOption(SHOW_IDENTIFIER_OPTION_NAME, false, helpLoc,
			"Show source file identifier info");
		showIdentifier = fieldOptions.getBoolean(SHOW_IDENTIFIER_OPTION_NAME, false);

	}

	private List<SourceMapEntry> getSourceMapEntries(CodeUnit cu) {
		List<SourceMapEntry> entries = new ArrayList<>();
		SourceFileManager sourceManager = cu.getProgram().getSourceFileManager();
		// check all addresses in the code unit to handle the (presumably rare) case where
		// there is an entry associated with an address in the code unit which is not its
		// minimum address
		Address cuMinAddr = cu.getMinAddress();
		Address cuMaxAddr = cu.getMaxAddress();
		SourceMapEntryIterator entryIter =
			sourceManager.getSourceMapEntryIterator(cuMaxAddr, false);
		while (entryIter.hasNext()) {
			SourceMapEntry entry = entryIter.next();
			long entryLength = entry.getLength();
			long adjusted = entryLength == 0 ? 0 : entryLength - 1;
			if (entry.getBaseAddress().add(adjusted).compareTo(cuMinAddr) >= 0) {
				entries.add(entry);
				continue;
			}
			if (entryLength != 0) {
				break;
			}
		}
		return entries.reversed();
	}

}
