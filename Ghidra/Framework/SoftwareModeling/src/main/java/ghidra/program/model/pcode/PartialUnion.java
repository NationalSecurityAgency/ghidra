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
package ghidra.program.model.pcode;

import javax.help.UnsupportedOperationException;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;

/**
 * A data-type representing an unspecified piece of a parent Union data-type.  This is used
 * internally by the decompiler to label Varnodes representing partial symbols, where the
 * part is known to be contained in a Union data-type.  Within the isolated context of a Varnode,
 * its not possible to resolve to a specific field of the Union because the Varnode may be used
 * in multiple ways.
 */
public class PartialUnion extends AbstractDataType {
	private DataType unionDataType;	// Either a Union or a Typedef of a Union
	private int offset;			// Offset in bytes of partial within parent
	private int size;			// Number of bytes in partial

	PartialUnion(DataTypeManager dtm, DataType parent, int off, int sz) {
		super(CategoryPath.ROOT, "partialunion", dtm);
		unionDataType = parent;
		offset = off;
		size = sz;
	}

	/**
	 * @return the Union data-type of which this is a part
	 */
	public DataType getParent() {
		return unionDataType;
	}

	/**
	 * @return the offset, in bytes, of this part within its parent Union
	 */
	public int getOffset() {
		return offset;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		// Internal to the PcodeDataTypeManager
		throw new UnsupportedOperationException("may not be cloned");
	}

	@Override
	public int getLength() {
		return size;
	}

	@Override
	public int getAlignedLength() {
		return getLength();
	}

	@Override
	public String getDescription() {
		return "Partial Union (internal)";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return null;	// Should not be placed on memory
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		return null;	// Should not be placed on memory
	}

	@Override
	public SettingsDefinition[] getSettingsDefinitions() {
		return unionDataType.getSettingsDefinitions();
	}

	@Override
	public Settings getDefaultSettings() {
		return unionDataType.getDefaultSettings();
	}

	@Override
	public DataType copy(DataTypeManager dtm) {
		// Internal to the PcodeDataTypeManager
		throw new UnsupportedOperationException("may not be copied");
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return unionDataType.getValueClass(settings);
	}

	@Override
	public boolean isEquivalent(DataType dt) {
		if (dt == null || !(dt instanceof PartialUnion)) {
			return false;
		}
		PartialUnion op = (PartialUnion) dt;
		if (offset != op.offset || size != op.size) {
			return false;
		}
		return unionDataType.isEquivalent(op.unionDataType);
	}

	@Override
	public int getAlignment() {
		return 0;
	}

	/**
	 * Get a data-type that can be used as a formal replacement for this (internal) data-type
	 * @return a replacement data-type
	 */
	public DataType getStrippedDataType() {
		return Undefined.getUndefinedDataType(size);
	}
}
