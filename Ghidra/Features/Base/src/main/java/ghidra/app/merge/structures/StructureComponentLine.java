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
package ghidra.app.merge.structures;

import java.util.List;
import java.util.Objects;

import org.apache.commons.lang3.StringUtils;

import ghidra.program.model.data.*;

/**
 * {@link CoordinatedStructureLine} for showing structure components.
 */
public class StructureComponentLine extends CoordinatedStructureLine {
	public static final int COMPONENT_INDENT = 5;
	public static final int OFFSET_SIZE = 10;
	public static final int MIN_DT_SIZE = 100;
	public static final int MIN_NAME_SIZE = 10;
	public static final int MIN_COMMENT_SIZE = 10;
	private DataTypeComponent mergedComp;
	private int offset;
	private int length;
	private Structure mergedStruct;

	/**
	 * Constructor
	 * @param model the {@link CoordinatedStructureModel}
	 * @param leftStruct the left structure
	 * @param rightStruct the right structure
	 * @param mergedStruct the merged structure
	 * @param left the left component at the offset (can be null)
	 * @param right the right component at the offset (can be null)
	 * @param merged the merged component at the offset (can be null)
	 * @param offset the offset into the structures for this component line
	 * @param length the size of the this component line (will be the largest of the three)
	 * @param line the line number where this component will be shown in the overall list of 
	 * line items (including name, description, info, etc.)
	 */
	StructureComponentLine(CoordinatedStructureModel model, Structure leftStruct,
			Structure rightStruct,
			Structure mergedStruct, DataTypeComponent left, DataTypeComponent right,
			DataTypeComponent merged, int offset, int length, int line) {
		super(model);
		this.mergedStruct = mergedStruct;
		this.left = new StructureComponentItem(left, right, leftStruct, line);
		this.right = new StructureComponentItem(right, left, rightStruct, line);
		this.merged = new StructureComponentItem(merged, null, mergedStruct, line);
		this.mergedComp = merged;
		this.offset = offset;
		this.length = length;
	}

	int getSize() {
		return length;
	}

	int getOffset() {
		return offset;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		StructureComponentLine other = (StructureComponentLine) obj;
		return Objects.equals(left, other.left) && length == other.length &&
			Objects.equals(merged, other.merged) && offset == other.offset &&
			Objects.equals(right, other.right);
	}

	@Override
	public String toString() {
		StringBuilder buf = new StringBuilder();
		buf.append("\nLeft: ");
		buf.append(left.toString());
		buf.append("\n");
		buf.append("Right: ");
		buf.append(right.toString());
		buf.append("\n");
		buf.append("Merged: ");
		buf.append(merged.toString());
		buf.append("\n");
		buf.append("offset = ");
		buf.append(offset);
		buf.append(", length = ");
		buf.append(length);
		buf.append("\n");
		return buf.toString();
	}

	/**
	 * Class for the individual {@link ComparisonItem}s for each of the structures.
	 */
	private class StructureComponentItem extends ComparisonItem {
		private static final int OFFSET_COL = 1;
		private static final int DATATYPE_COL = 2;
		private static final int NAME_COL = 3;
		private static final int COMMENT_COL = 4;

		private DataTypeComponent myComp;
		private DataTypeComponent otherComp;
		private Structure struct;

		StructureComponentItem(DataTypeComponent comp, DataTypeComponent other, Structure struct,
				int line) {
			super("Component", line);
			this.myComp = comp;
			this.otherComp = other;
			this.struct = struct;
		}

		@Override
		public String getColumnText(int column) {
			if (myComp == null) {
				return "";
			}
			switch (column) {
				case OFFSET_COL:
					return Integer.toString(offset) + "    ";
				case DATATYPE_COL:
					DataType dataType = myComp.getDataType();
					if (dataType == DataType.DEFAULT) {
						return "undefined (" + getUndefinedLength() + ")";
					}
					return getDataTypeDisplayName(dataType);
				case NAME_COL:
					String name = myComp.getFieldName();
					return name == null ? "" : name;
				case COMMENT_COL:
					String comment = myComp.getComment();
					return StringUtils.isBlank(comment) ? "" : "// " + comment;
				default:
					return "";
			}
		}

		private String getDataTypeDisplayName(DataType dataType) {
			String name = dataType.getDisplayName();
			if (dataType instanceof BitFieldDataType bfdt) {
				int startBit = bfdt.getBitOffset();
				int endBit = startBit + bfdt.getBitSize() - 1;
				name += " (%d, %d)".formatted(startBit, endBit);
			}
			return name;
		}

		private int getUndefinedLength() {
			// loop until we find the next line that has a different offset than this line
			// The difference will be the undefined length;
			for (int i = getLine() + 1; i < model.getSize(); i++) {
				CoordinatedStructureLine compareLine = model.getLine(i);
				if (!(compareLine instanceof StructureComponentLine componentLine)) {
					break;
				}
				if (componentLine.offset != offset) {
					return componentLine.offset - offset;
				}
			}
			// otherwise, the length is to the end of the struct
			return struct.getLength() - offset;
		}

		@Override
		public boolean isLeftJustified(int column) {
			return column != 1;
		}

		@Override
		public int getMinWidth(int column) {
			switch (column) {
				case 0:
					return COMPONENT_INDENT;
				case OFFSET_COL:
					return OFFSET_SIZE;
				case DATATYPE_COL:
					return MIN_DT_SIZE;
				case NAME_COL:
					return MIN_NAME_SIZE;
				case COMMENT_COL:
					return MIN_COMMENT_SIZE;
				default:
					return 0;
			}
		}

		@Override
		public boolean canApplyAny() {
			if (myComp == mergedComp) {
				return false;
			}

			return !(isDatatypeApplied() && isNameApplied() && isCommentApplied());
		}

		@Override
		public boolean isAppliable() {
			if (myComp == null || myComp.getDataType() == DataType.DEFAULT) {
				return false;
			}
			if (otherComp == null) {
				return true;
			}
			return !myComp.isEquivalent(otherComp);
		}

		@Override
		public boolean isAppliable(int column) {
			if (myComp == mergedComp) {
				return false;
			}
			if (myComp == null || myComp == mergedComp ||
				myComp.getDataType() == DataType.DEFAULT) {
				return false;
			}
			return column == DATATYPE_COL || column == NAME_COL || column == COMMENT_COL;
		}

		@Override
		public boolean isApplied(int column) {
			if (myComp == null || mergedComp == null) {
				return false;
			}

			switch (column) {
				case DATATYPE_COL:
					return isDatatypeApplied();
				case NAME_COL:
					return isNameApplied();
				case COMMENT_COL:
					return isNameApplied();
				default:
					return false;
			}
		}

		@Override
		public boolean canClear() {
			return mergedComp != null && mergedComp.getDataType() != DataType.DEFAULT;
		}

		@Override
		public int hashCode() {
			return myComp == null ? 0 : myComp.hashCode();
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			StructureComponentItem other = (StructureComponentItem) obj;
			if (myComp == null) {
				return other.myComp == null;
			}
			if (myComp.getOffset() != other.myComp.getOffset()) {
				return false;
			}
			if (!myComp.getDataType().isEquivalent(other.myComp.getDataType())) {
				return false;
			}
			if (!Objects.equals(myComp.getFieldName(), other.myComp.getFieldName())) {
				return false;
			}
			return Objects.equals(myComp.getComment(), other.myComp.getComment());
		}

		private boolean isDatatypeApplied() {
			if (myComp == null || mergedComp == null) {
				return false;
			}
			return myComp.getDataType().isEquivalent(mergedComp.getDataType());
		}

		private boolean isNameApplied() {
			if (myComp == null) {
				return false;
			}

			if (mergedComp == null) {
				return false;
			}
			return Objects.equals(myComp.getFieldName(), mergedComp.getFieldName());
		}

		private boolean isCommentApplied() {
			return Objects.equals(myComp.getComment(), mergedComp.getComment());
		}

		@Override
		public String toString() {
			if (myComp == null) {
				return "";
			}
			StringBuffer buffer = new StringBuffer();
			buffer.append(myComp.getOffset());
			buffer.append(" ");
			buffer.append(getColumnText(DATATYPE_COL));

			String name = myComp.getFieldName();
			if (name != null) {
				buffer.append(" " + name);
			}
			String comment = myComp.getComment();
			if (!StringUtils.isBlank(comment)) {
				buffer.append(" // ");
				buffer.append(comment);
			}
			return buffer.toString();
		}

		@Override
		public void applyAll() {
			if (myComp.getLength() == 0) {
				mergedStruct.insertAtOffset(offset, myComp.getDataType(), 0, myComp.getFieldName(),
					myComp.getComment());
			}
			else if (myComp.getDataType() instanceof BitFieldDataType bfdt) {
				makeRoomForBitField(bfdt);
				DataType dt = bfdt.getBaseDataType();
				int byteSize = bfdt.getStorageSize();
				int bitOffset = bfdt.getBitOffset();
				int bitLength = bfdt.getBitSize();
				String name = myComp.getFieldName();
				String comment = myComp.getComment();
				try {
					mergedStruct.insertBitFieldAt(offset, byteSize, bitOffset, dt, bitLength, name,
						comment);
				}
				catch (InvalidDataTypeException e) {
					model.error("Error applying bitfield component at offset " + offset + ": " +
						e.getMessage());
				}
			}
			else {
				makeRoom();
				mergedStruct.replaceAtOffset(offset, myComp.getDataType(), myComp.getLength(),
					myComp.getFieldName(), myComp.getComment());
			}
			modelChanged();
		}

		private void makeRoomForBitField(BitFieldDataType bfdt) {

			List<DataTypeComponent> comps = mergedStruct.getComponentsContaining(offset);
			for (DataTypeComponent comp : comps) {
				DataType dt = comp.getDataType();
				if (dt instanceof BitFieldDataType otherBfdt) {
					if (BitFieldDataType.intersects(bfdt, otherBfdt, offset, comp.getOffset())) {
						mergedStruct.clearComponent(comp.getOrdinal());
					}
				}
				else if (dt != DataType.DEFAULT && comp.getOffset() == offset &&
					comp.getLength() != 0) {
					mergedStruct.clearComponent(comp.getOrdinal());
				}
			}

			for (int i = offset + 1; i < offset + length; i++) {
				comps = mergedStruct.getComponentsContaining(i);
				for (DataTypeComponent comp : comps) {
					// To avoid repeating looking at components we already examined, only look
					// at components that start at the offset being examined. (We already
					// handled all the one that extend into the new component, so only need
					// to worry about the ones that start inside it.)
					if (comp.getOffset() != i) {
						continue;
					}
					DataType dt = comp.getDataType();
					if (dt instanceof BitFieldDataType otherBfdt) {
						if (BitFieldDataType.intersects(bfdt, otherBfdt, offset, i)) {
							mergedStruct.clearComponent(comp.getOrdinal());
						}
					}
					else {
						// if we have anything other than a bitfield, then wipe them all out
						// because only bitfields can coexist with other bitfields.
						mergedStruct.clearAtOffset(i);
						return;
					}
				}
			}
		}

		@Override
		public void clear() {
			mergedStruct.clearComponent(mergedComp.getOrdinal());
			modelChanged();
		}

		private void makeRoom() {
			if (myComp.getLength() == 0) {
				// just make sure there is that starts here
				if (mergedStruct.getComponentAt(offset) == null) {
					mergedStruct.clearAtOffset(offset);
				}
				return;
			}

			List<DataTypeComponent> list = mergedStruct.getComponentsContaining(offset);
			for (DataTypeComponent comp : list) {
				DataType dt = comp.getDataType();
				if (dt != DataType.DEFAULT && comp.getOffset() == offset && comp.getLength() != 0) {
					mergedStruct.clearComponent(comp.getOrdinal());
				}
			}

			for (int i = offset + 1; i < offset + length; i++) {
				mergedStruct.clearAtOffset(i);
			}
		}

		@Override
		public boolean isBlank() {
			return myComp == null;
		}
	}
}
