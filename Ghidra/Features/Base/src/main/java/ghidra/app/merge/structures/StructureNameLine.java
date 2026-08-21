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

import java.util.Objects;

import ghidra.program.model.data.Structure;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;

/**
 * {@link CoordinatedStructureLine} for showing the structure's name.
 */
public class StructureNameLine extends CoordinatedStructureLine {

	/**
	 * Constructor
	 * @param model the {@link CoordinatedStructureModel}
	 * @param leftStruct the left structure
	 * @param rightStruct the right structure
	 * @param mergedStruct the merged structure
	 * @param line the line number where this component will be shown in the overall list of 
	 * line items (including name, description, info, etc.)
	 */
	public StructureNameLine(CoordinatedStructureModel model, Structure leftStruct,
			Structure rightStruct, Structure mergedStruct, int line) {
		super(model);
		this.left = new NameItem(leftStruct, mergedStruct, line);
		this.right = new NameItem(rightStruct, mergedStruct, line);
		this.merged = new NameItem(mergedStruct, mergedStruct, line);
	}

	@Override
	public String toString() {
		StringBuilder buf = new StringBuilder();
		buf.append("Left name: ");
		buf.append(((NameItem) left).struct.getName());
		buf.append(", Right name: ");
		buf.append(((NameItem) right).struct.getName());
		buf.append(", Merged name: ");
		buf.append(((NameItem) merged).struct.getName());

		return buf.toString();
	}

	/**
	 * Class for the individual {@link ComparisonItem}s for each of the structures.
	 */
	private class NameItem extends ComparisonItem {
		private static final int STRUCT_KEYWORD_COL = 0;
		private static final int STRUCT_NAME_COL = 1;
		private Structure struct;
		private Structure mergedStruct;

		NameItem(Structure struct, Structure mergedStruct, int line) {
			super("Structure Name", line);
			this.struct = struct;
			this.mergedStruct = mergedStruct;
		}

		@Override
		public String getColumnText(int column) {
			switch (column) {
				case STRUCT_KEYWORD_COL:
					return "Struct";
				case STRUCT_NAME_COL:
					return struct.getName();
				default:
					return "";
			}
		}

		@Override
		public boolean canApplyAny() {
			return !isApplied(STRUCT_NAME_COL);
		}

		@Override
		public boolean isAppliable() {
			return true;
		}

		@Override
		public boolean isAppliable(int column) {
			if (struct == mergedStruct) {
				return false;		// cant apply the results to itself
			}
			return column == STRUCT_NAME_COL;
		}

		@Override
		public boolean isApplied(int column) {
			if (column == STRUCT_NAME_COL) {
				return struct.getName().equals(mergedStruct.getName());
			}
			return false;
		}

		@Override
		public int getMinWidth(int column) {
			switch (column) {
				case 0:
					return -1;
				case 1:
					return 200;
				default:
					return 0;
			}
		}

		@Override
		public int hashCode() {
			return struct.getName().hashCode();
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
			NameItem other = (NameItem) obj;
			return Objects.equals(struct.getName(), other.struct.getName());
		}

		@Override
		public String toString() {
			return "Struct " + struct.getName();
		}

		@Override
		public void applyAll() {
			try {
				mergedStruct.setName(struct.getName());
				modelChanged();
			}
			catch (InvalidNameException | DuplicateNameException e) {
				error("Error applying structure name: " + e.getMessage());
			}
		}

		@Override
		public boolean isBlank() {
			return false;
		}
	}
}
