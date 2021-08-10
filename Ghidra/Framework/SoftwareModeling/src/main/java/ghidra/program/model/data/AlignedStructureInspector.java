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
package ghidra.program.model.data;

import java.util.ArrayList;
import java.util.List;

import javax.help.UnsupportedOperationException;

import ghidra.docking.settings.Settings;
import ghidra.util.exception.DuplicateNameException;

/**
 * <code>AlignedStructureInspector</code> provides a simple instance of a structure 
 * member container used to perform alignment operations without forcing modification
 * of the actual structure.
 */
public class AlignedStructureInspector extends AlignedStructurePacker {

	private AlignedStructureInspector(StructureInternal structure) {
		super(structure, getComponentWrappers(structure));
	}

	private static List<ReadOnlyComponentWrapper> getComponentWrappers(Structure structure) {
		List<ReadOnlyComponentWrapper> list = new ArrayList<>();
		for (DataTypeComponent c : structure.getDefinedComponents()) {
			list.add(new ReadOnlyComponentWrapper(c));
		}
		return list;
	}

	private static class ReadOnlyComponentWrapper implements InternalDataTypeComponent {

		private final DataTypeComponent component;

		private int ordinal;
		private int offset;
		private int length;
		private DataType dataType;

		ReadOnlyComponentWrapper(DataTypeComponent component) {
			this.component = component;
			this.ordinal = component.getOrdinal();
			this.offset = component.getOffset();
			this.length = component.getLength();
			this.dataType = component.getDataType();
		}

		@Override
		public void update(int ord, int off, int len) {
			this.ordinal = ord;
			this.offset = off;
			this.length = len;
		}

		@Override
		public DataType getDataType() {
			return dataType;
		}

		@Override
		public DataType getParent() {
			return component.getParent();
		}

		@Override
		public boolean isBitFieldComponent() {
			return component.isBitFieldComponent();
		}

		@Override
		public boolean isZeroBitFieldComponent() {
			return component.isZeroBitFieldComponent();
		}

		@Override
		public int getOrdinal() {
			return ordinal;
		}

		@Override
		public int getOffset() {
			return offset;
		}

		@Override
		public int getEndOffset() {
			return offset + length - 1;
		}

		@Override
		public int getLength() {
			return length;
		}

		@Override
		public String getComment() {
			return component.getComment();
		}

		@Override
		public Settings getDefaultSettings() {
			return component.getDefaultSettings();
		}

		@Override
		public void setDefaultSettings(Settings settings) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void setComment(String comment) {
			throw new UnsupportedOperationException();
		}

		@Override
		public String getFieldName() {
			return component.getFieldName();
		}

		@Override
		public void setFieldName(String fieldName) throws DuplicateNameException {
			throw new UnsupportedOperationException();
		}

		@Override
		public String getDefaultFieldName() {
			if (isZeroBitFieldComponent()) {
				return "";
			}
			return DEFAULT_FIELD_NAME_PREFIX + "_0x" + Integer.toHexString(getOffset());
		}

		@Override
		public boolean isEquivalent(DataTypeComponent dtc) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void setDataType(DataType dataType) {
			this.dataType = dataType;
		}

	}

	/**
	 * Perform structure component packing in a read-only fashion primarily
	 * for the purpose of computing external alignment for existing structures.
	 * @param structure
	 * @return aligned packing result
	 */
	public static StructurePackResult packComponents(StructureInternal structure) {
		AlignedStructureInspector packer = new AlignedStructureInspector(structure);
		return packer.pack();
	}

}
