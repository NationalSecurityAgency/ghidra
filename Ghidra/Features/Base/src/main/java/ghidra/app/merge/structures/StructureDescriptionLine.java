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

import org.apache.commons.lang3.StringUtils;

import ghidra.program.model.data.Structure;

/**
 * {@link CoordinatedStructureLine} for showing structure description (its comment).
 */
public class StructureDescriptionLine extends CoordinatedStructureLine {

	/**
	 * Constructor
	 * @param model the {@link CoordinatedStructureModel}
	 * @param leftStruct the left structure
	 * @param rightStruct the right structure
	 * @param mergedStruct the merged structure
	 * @param line the line number where this component will be shown in the overall list of 
	 * line items (including name, description, info, etc.)
	 */
	public StructureDescriptionLine(CoordinatedStructureModel model, Structure leftStruct,
			Structure rightStruct, Structure mergedStruct, int line) {
		super(model);
		this.left = new DescriptionItem(leftStruct, mergedStruct, line);
		this.right = new DescriptionItem(rightStruct, mergedStruct, line);
		this.merged = new DescriptionItem(mergedStruct, mergedStruct, line);
	}

	@Override
	public String toString() {
		StringBuilder buf = new StringBuilder();
		buf.append("Left name: ");
		buf.append(((DescriptionItem) left).struct.getName());
		buf.append(", Right name: ");
		buf.append(((DescriptionItem) right).struct.getName());
		buf.append(", Merged name: ");
		buf.append(((DescriptionItem) merged).struct.getName());

		return buf.toString();
	}

	/**
	 * Class for the individual {@link ComparisonItem}s for each of the structures.
	 */
	private class DescriptionItem extends ComparisonItem {
		private static final int STRUCT_COMMENT_COL = 0;
		private Structure struct;
		private Structure mergedStruct;

		DescriptionItem(Structure struct, Structure mergedStruct, int line) {
			super("Structure Comment", line);
			this.struct = struct;
			this.mergedStruct = mergedStruct;
		}

		@Override
		public String getColumnText(int column) {
			if (column != STRUCT_COMMENT_COL) {
				return "";
			}
			String description = struct.getDescription();

			if (!StringUtils.isBlank(description)) {
				description = "// " + description;
			}
			return description;
		}

		@Override
		public boolean canApplyAny() {
			return !isApplied(STRUCT_COMMENT_COL);
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
			return column == STRUCT_COMMENT_COL;
		}

		@Override
		public boolean isApplied(int column) {
			if (column == STRUCT_COMMENT_COL) {
				return Objects.equals(struct.getDescription(), mergedStruct.getDescription());
			}
			return false;
		}

		@Override
		public int getMinWidth(int column) {
			return column == STRUCT_COMMENT_COL ? 200 : 0;
		}

		@Override
		public int hashCode() {
			return struct.getName().hashCode();
		}

		@Override
		public String toString() {
			String description = struct.getDescription();
			if (StringUtils.isBlank(description)) {
				return "";
			}
			return "// " + description;
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
			DescriptionItem other = (DescriptionItem) obj;
			return Objects.equals(struct.getDescription(), other.struct.getDescription());
		}

		@Override
		public void applyAll() {
			String description = struct.getDescription();
			mergedStruct.setDescription(description);
			modelChanged();
		}

		@Override
		public boolean isBlank() {
			return StringUtils.isBlank(struct.getDescription());
		}
	}
}
