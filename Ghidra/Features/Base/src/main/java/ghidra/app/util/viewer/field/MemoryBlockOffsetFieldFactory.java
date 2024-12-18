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

import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.OffsetFieldType;

/**
 *  Generates {@link MemoryBlock} Offset fields
 */
public class MemoryBlockOffsetFieldFactory extends AbstractOffsetFieldFactory {

	private static final String FIELD_OFFSET_DESCRIPTION = "MemoryBlock";
	private static final String FIELD_NAME_DESCRIPTION = "Memory Block";

	/**
	 * Creates a new default {@link MemoryBlockOffsetFieldFactory}
	 */
	public MemoryBlockOffsetFieldFactory() {
		super(FIELD_OFFSET_DESCRIPTION);
	}

	/**
	 * Creates a new {@link MemoryBlockOffsetFieldFactory}
	 * 
	 * @param model the {@link FieldFormatModel} that the field belongs to
	 * @param hlProvider the {@link ListingHighlightProvider}
	 * @param displayOptions the {@link Options} for display properties
	 * @param fieldOptions the {@link Options} for field specific properties
	 */
	private MemoryBlockOffsetFieldFactory(FieldFormatModel model,
			ListingHighlightProvider hlProvider, Options displayOptions, Options fieldOptions) {
		super(FIELD_OFFSET_DESCRIPTION, FIELD_NAME_DESCRIPTION, model, hlProvider, displayOptions,
			fieldOptions);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel,
			ListingHighlightProvider highlightProvider, ToolOptions options,
			ToolOptions fieldOptions) {
		return new MemoryBlockOffsetFieldFactory(formatModel, highlightProvider, options,
			fieldOptions);
	}

	@Override
	public String getOffsetValue(CodeUnit cu) {
		Address addr = cu.getAddress();
		String text = "";
		MemoryBlock block = cu.getProgram().getMemory().getBlock(addr);
		if (block != null) {
			long offset = addr.subtract(block.getStart());
			text = String.format(useHex ? "0x%x" : "%d", offset);
			if (showName) {
				text = "%s:%s".formatted(block.getName(), text);
			}
		}
		return text;
	}

	@Override
	public OffsetFieldType getOffsetFieldType() {
		return OffsetFieldType.MEMORYBLOCK;
	}
}
