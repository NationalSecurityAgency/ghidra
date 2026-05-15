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

/**
 * {@link CoordinatedStructureLine} for showing invariant structure information. This includes
 * syntax ("{" and "}") and structure details (size, alignment, packing). 
 */
public class StructureInfoLine extends CoordinatedStructureLine {

	/**
	 * Constructor
	 * @param model the {@link CoordinatedStructureModel}
	 * @param left the string to be displayed in the left display
	 * @param right the string to be displayed in the right display
	 * @param merged the string to be displayed in the merged display
	 * @param line the line number of this line in the overall display
	 * @param type the type of info ("Syntax", or "Structure details")
	 */
	public StructureInfoLine(CoordinatedStructureModel model, String left, String right,
			String merged, int line, String type) {
		super(model);
		this.left = new InfoItem(left, type, line);
		this.right = new InfoItem(right, type, line);
		this.merged = new InfoItem(merged, type, line);
	}

	/**
	 * Constructor
	 * @param model the {@link CoordinatedStructureModel}
	 * @param all the string to be displayed in all displays
	 * @param line the line number of this line in the overall display
	 * @param type the type of info ("Syntax", or "Structure details")
	 */
	public StructureInfoLine(CoordinatedStructureModel model, String all, int line, String type) {
		this(model, all, all, all, line, type);
	}

	@Override
	public String toString() {
		StringBuilder buf = new StringBuilder();
		buf.append("left: ");
		buf.append(((InfoItem) left).info);
		buf.append(", right: ");
		buf.append(((InfoItem) right).info);
		buf.append(", merged: ");
		buf.append(((InfoItem) merged).info);
		return buf.toString();
	}

	/**
	 * Class for the individual {@link ComparisonItem}s for each of the structures.
	 */
	private class InfoItem extends ComparisonItem {

		private String info;

		InfoItem(String info, String type, int line) {
			super(type, line);
			this.info = info;
		}

		@Override
		public String getColumnText(int column) {
			if (column == 0) {
				return info;
			}
			return "";
		}

		@Override
		public int getMinWidth(int column) {
			return column == 0 ? 350 : 0;
		}

		@Override
		public int hashCode() {
			return info.hashCode();
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
			InfoItem other = (InfoItem) obj;
			return Objects.equals(info, other.info);
		}

		@Override
		public String toString() {
			return info;
		}
	}
}
