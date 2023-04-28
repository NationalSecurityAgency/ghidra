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

import java.beans.PropertyEditor;
import java.math.BigInteger;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import generic.theme.GColor;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.*;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.util.FileOffsetFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.exception.AssertException;

/**
 *  Generates File Offset fields
 */
public class FileOffsetFieldFactory extends FieldFactory {

	public static final String FIELD_NAME = "File Offset";
	public static final GColor COLOR = new GColor("color.fg.listing.file.offset");
	public static final String GROUP_TITLE = "File Offset Field";
	public final static String FILE_OFFSET_DISPLAY_OPTIONS_NAME =
		GROUP_TITLE + Options.DELIMITER + "File Offset Display Options";

	private boolean showFilename;
	private boolean useHex;
	private PropertyEditor fileOffsetFieldOptionsEditor =
		new FileOffsetFieldOptionsPropertyEditor();

	/**
	 * Default Constructor
	 */
	public FileOffsetFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private FileOffsetFieldFactory(FieldFormatModel model, ListingHighlightProvider hlProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);
		initOptions(fieldOptions);
	}

	private void initOptions(Options fieldOptions) {
		HelpLocation helpLoc = new HelpLocation("CodeBrowserPlugin", "File_Offset_Field");

		fieldOptions.registerOption(FILE_OFFSET_DISPLAY_OPTIONS_NAME, OptionType.CUSTOM_TYPE,
			new FileOffsetFieldOptionsWrappedOption(), helpLoc,
			"Adjusts the File Offset Field display", fileOffsetFieldOptionsEditor);

		CustomOption customOption =
			fieldOptions.getCustomOption(FILE_OFFSET_DISPLAY_OPTIONS_NAME, null);

		if (!(customOption instanceof FileOffsetFieldOptionsWrappedOption)) {
			throw new AssertException("Someone set an option for " +
				FILE_OFFSET_DISPLAY_OPTIONS_NAME + " that is not the expected " +
				FileOffsetFieldOptionsWrappedOption.class.getName() + " type.");
		}
		FileOffsetFieldOptionsWrappedOption fofowo =
			(FileOffsetFieldOptionsWrappedOption) customOption;
		showFilename = fofowo.showFilename();
		useHex = fofowo.useHex();

		fieldOptions.getOptions(GROUP_TITLE).setOptionsHelpLocation(helpLoc);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel,
			ListingHighlightProvider highlightProvider, ToolOptions options, ToolOptions fieldOptions) {
		return new FileOffsetFieldFactory(formatModel, highlightProvider, options, fieldOptions);
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionsName, Object oldValue,
			Object newValue) {
		if (optionsName.equals(FILE_OFFSET_DISPLAY_OPTIONS_NAME)) {
			FileOffsetFieldOptionsWrappedOption fofowo =
				(FileOffsetFieldOptionsWrappedOption) newValue;
			showFilename = fofowo.showFilename();
			useHex = fofowo.useHex();
			model.update();
		}
	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();
		if (!enabled || !(obj instanceof CodeUnit)) {
			return null;
		}

		CodeUnit cu = (CodeUnit) obj;
		Address addr = cu.getAddress();
		MemoryBlock block = cu.getProgram().getMemory().getBlock(addr);
		String text = "N/A";
		for (MemoryBlockSourceInfo sourceInfo : block.getSourceInfos()) {
			if (sourceInfo.contains(addr)) {
				if (sourceInfo.getFileBytes().isPresent()) {
					FileBytes fileBytes = sourceInfo.getFileBytes().get();
					long offset = sourceInfo.getFileBytesOffset(addr);
					if (useHex) {
						text = String.format("0x%x", offset);
					}
					else {
						text = String.format("%d", offset);
					}
					if (showFilename) {
						text = fileBytes.getFilename() + ":" + text;
					}
					break;
				}
			}
		}
		FieldElement fieldElement =
			new TextFieldElement(new AttributedString(text, COLOR, getMetrics()), 0, 0);
		ListingTextField listingTextField = ListingTextField.createSingleLineTextField(this, proxy,
			fieldElement, startX + varWidth, width, hlProvider);
		listingTextField.setPrimary(true);

		return listingTextField;
	}

	@Override
	public FieldLocation getFieldLocation(ListingField lf, BigInteger index, int fieldNum,
			ProgramLocation loc) {

		if (loc instanceof FileOffsetFieldLocation) {
			FileOffsetFieldLocation fileOffsetFieldLoc = (FileOffsetFieldLocation) loc;
			Object obj = lf.getProxy().getObject();

			if (obj instanceof CodeUnit && hasSamePath(lf, fileOffsetFieldLoc)) {
				return new FieldLocation(index, fieldNum, 0, fileOffsetFieldLoc.getCharOffset());
			}
		}

		return null;
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField lf) {
		Object obj = lf.getProxy().getObject();
		if (!(obj instanceof CodeUnit)) {
			return null;
		}
		CodeUnit cu = (CodeUnit) obj;

		Address addr = cu.getMinAddress();

		int[] cpath = null;
		if (cu instanceof Data) {
			cpath = ((Data) cu).getComponentPath();
		}

		return new FileOffsetFieldLocation(cu.getProgram(), addr, cpath, col);
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		if (!CodeUnit.class.isAssignableFrom(proxyObjectClass)) {
			return false;
		}
		return (category == FieldFormatModel.INSTRUCTION_OR_DATA ||
			category == FieldFormatModel.OPEN_DATA || category == FieldFormatModel.ARRAY);
	}
}
