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
import docking.widgets.fieldpanel.support.RowColLocation;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.program.util.MemoryBlockStartFieldLocation;
import ghidra.program.util.ProgramLocation;

/**
  *  Generates a text label on each {@link CodeUnit} that marks the start of a memory block. The
  *  label will will appear as part of the PLATE group in the field map.
  */
public class MemoryBlockStartFieldFactory extends FieldFactory {

	private static final String FIELD_NAME = "Memory Block Start";
	private static final Color BLOCK_COLOR = new Color(75, 0, 130);

	/**
	 * Constructor
	 */
	public MemoryBlockStartFieldFactory() {
		super(FIELD_NAME);
		color = BLOCK_COLOR;
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hsProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private MemoryBlockStartFieldFactory(FieldFormatModel model, HighlightProvider hlProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);
		color = BLOCK_COLOR;
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getField(ProxyObj, int)
	 */
	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {

		if (!enabled) {
			return null;
		}

		// Exit if we're not at a code unit.
		Object obj = proxy.getObject();
		if (!(obj instanceof CodeUnit)) {
			return null;
		}
		CodeUnit cu = (CodeUnit) obj;

		// Create the text block we want to show.
		List<AttributedString> attributedStrings = createBlockStartText(cu);
		if (attributedStrings == null || attributedStrings.isEmpty()) {
			return null;
		}

		// Convert the text to field elements.
		FieldElement[] elements = createFieldElements(attributedStrings);

		// And put the elements in a text field.
		ListingTextField ltf = ListingTextField.createMultilineTextField(this, proxy, elements,
			startX + varWidth, width, 10, hlProvider);
		ltf.setPrimary(true);

		return ltf;
	}

	/**
	 * Overridden to ensure that we return a {@link MemoryBlockStartFieldLocation} instance.
	 * 
	 * @see ghidra.app.util.viewer.field.FieldFactory#getProgramLocation(int, int, ghidra.app.util.viewer.field.ListingField)
	 */
	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {

		Object proxyObject = bf.getProxy().getObject();
		if (!(proxyObject instanceof CodeUnit)) {
			return null;
		}
		CodeUnit cu = (CodeUnit) proxyObject;

		String[] comments;
		List<AttributedString> attributedStrings = createBlockStartText(cu);
		if (attributedStrings == null) {
			comments = new String[0];
		}
		else {
			comments = new String[attributedStrings.size()];
			for (int i = 0; i < comments.length; i++) {
				comments[i] = attributedStrings.get(i).getText();
			}
		}

		return new MemoryBlockStartFieldLocation(cu.getProgram(), cu.getMinAddress(), null, row,
			col, comments, 0);
	}

	/**
	 * Overridden to ensure that we only place block comments on the first {@link CodeUnit} of 
	 * the block.
	 * 
	 * @see ghidra.app.util.viewer.field.FieldFactory#getFieldLocation(ghidra.app.util.viewer.field.ListingField, BigInteger, int, ghidra.program.util.ProgramLocation)
	 */
	@Override
	public FieldLocation getFieldLocation(ListingField listingField, BigInteger index, int fieldNum,
			ProgramLocation programLoc) {

		// Only handle this if it's the right kind of location object.
		if (!(programLoc instanceof MemoryBlockStartFieldLocation)) {
			return null;
		}
		MemoryBlockStartFieldLocation blockLocation = (MemoryBlockStartFieldLocation) programLoc;

		Object obj = listingField.getProxy().getObject();
		if (obj instanceof CodeUnit) {
			CodeUnit cu = (CodeUnit) obj;

			MemoryBlock block = cu.getMemory().getBlock(cu.getAddress());
			if (block == null) {
				return null;
			}

			// If the code unit does NOT rest at the beginning of a memory block, no need
			// to handle this.
			if (cu.getMinAddress().equals(block.getStart())) {

				if (listingField instanceof ListingTextField) {
					ListingTextField listingTextField = (ListingTextField) listingField;

					RowColLocation location = listingTextField.dataToScreenLocation(
						blockLocation.getRow(), blockLocation.getCharOffset());

					return new FieldLocation(index, fieldNum, location.row(), location.col());
				}
			}
		}

		return null;
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#acceptsType(int, java.lang.Class)
	 */
	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		return (category == FieldFormatModel.PLATE);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel, HighlightProvider provider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		return new MemoryBlockStartFieldFactory(formatModel, provider, displayOptions,
			fieldOptions);
	}

	/**
	 * Creates a comment to be show at the beginning of each block that shows the following:
	 *   - block name
	 *   - block type
	 *   - block start/end address (size)
	 *   - block comment
	 * 
	 * @param cu
	 */
	protected List<AttributedString> createBlockStartText(CodeUnit cu) {

		List<AttributedString> lines = new ArrayList<>();

		// Need to get the memory block that this code unit is a part of, so we can check
		// its start address.
		MemoryBlock block = cu.getMemory().getBlock(cu.getAddress());

		if (block == null) {
			return null;
		}

		// If the code unit is not at the start of the block, just return.
		if (!(cu.getMinAddress().equals(block.getStart()))) {
			return null;
		}

		MemoryBlockType blockType = block.getType();

		String type = "";
		if (blockType != MemoryBlockType.DEFAULT) {
			if (block.isMapped()) {
				type = "(" + block.getSourceInfos().get(0).getDescription() + ")";
			}
			else {
				type = "(" + blockType + ")";
			}
		}
		String line1 = block.getName() + " " + type;
		String line2 = block.getComment();
		String line3 = block.getStart().toString(true) + "-" + block.getEnd().toString(true);

		AttributedString borderAS = new AttributedString("//", color, getMetrics());
		lines.add(borderAS);
		lines.add(new AttributedString("// " + line1, color, getMetrics()));
		if (line2 != null && !line2.isEmpty()) {
			lines.add(new AttributedString("// " + line2, color, getMetrics()));
		}
		lines.add(new AttributedString("// " + line3, color, getMetrics()));
		lines.add(borderAS);

		return lines;
	}

	/**
	 * Creates {@link FieldElement} instances for each given {@link AttributedString}.
	 * 
	 * @param attributedStrings
	 * @return
	 */
	private FieldElement[] createFieldElements(List<AttributedString> attributedStrings) {
		List<FieldElement> elements = new ArrayList<>();
		int lineNum = 0;
		for (AttributedString line : attributedStrings) {
			FieldElement blockElement = new TextFieldElement(line, lineNum, 0);
			elements.add(blockElement);
			lineNum++;
		}

		// Convert to an array
		FieldElement[] elementsArray = new FieldElement[elements.size()];
		elements.toArray(elementsArray);

		return elementsArray;
	}

	/**
	 * Returns the length of the longest string in the given list.
	 * 
	 * @param lines
	 * @return
	 */
	private int getLongestLineSize(String... lines) {

		int longest = 0;
		for (String line : lines) {
			if (line.length() > longest) {
				longest = line.length();
			}
		}
		return longest;

	}

}
