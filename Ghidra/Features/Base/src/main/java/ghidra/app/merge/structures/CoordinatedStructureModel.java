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

import java.util.*;
import java.util.function.Consumer;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.merge.structures.CoordinatedStructureLine.CompareId;
import ghidra.program.database.data.merge.DataTypeMergeException;
import ghidra.program.database.data.merge.StructureMerger;
import ghidra.program.model.data.*;
import util.CollectionUtils;
import utility.function.Callback;

/**
 * Model for merging two structures in an interactive dialog. The first structure will be considered
 * the left structure (it will be displayed on the left side) and the second structure will be
 * considered the right structure. This class will internally generate a merged structure by 
 * combining the two given structures. Initially, if there is a conflict, the first structure (left)
 * will be given precedence.
 */
public class CoordinatedStructureModel {

	private Structure leftStruct;
	private Structure rightStruct;
	private Structure mergedStruct;
	private List<CoordinatedStructureLine> compareLines;
	private Consumer<String> errorHandler;
	private List<Callback> changeCallbacks = new ArrayList<>();

	/**
	 * Constructor
	 * @param struct1 the left structure (has initial precedence for conflicts)
	 * @param struct2 the right structure
	 * @param errorHandler a consumer for reporting errors
	 */
	public CoordinatedStructureModel(Structure struct1, Structure struct2,
			Consumer<String> errorHandler) {
		this.leftStruct = struct1;
		this.errorHandler = errorHandler;

		// make sure struct2 has same data organization as struct1
		this.rightStruct = struct2.clone(struct1.getDataTypeManager());
		StructureMerger merger = new StructureMerger(struct1, struct2, false);
		try {
			this.mergedStruct = merger.merge();
		}
		catch (DataTypeMergeException e) {
			this.mergedStruct = (Structure) struct1.copy(struct1.getDataTypeManager());
		}

		compareLines = buildLines();
	}

	/**
	 * Completely rebuilds all the structure compare lines. Called whenever any change is made to
	 * the merged structure.
	 */
	void rebuild() {
		compareLines = buildLines();
		for (Callback callback : changeCallbacks) {
			callback.call();
		}
	}

	private List<CoordinatedStructureLine> buildLines() {
		List<CoordinatedStructureLine> list = new ArrayList<>();
		LineBuilder lineBuilder = new LineBuilder(list);

		String description1 = leftStruct.getDescription();
		String description2 = rightStruct.getDescription();
		if (!StringUtils.isBlank(description1) || !StringUtils.isBlank(description2)) {
			list.add(new StructureDescriptionLine(this, leftStruct, rightStruct, mergedStruct,
				list.size()));
		}

		list.add(new StructureNameLine(this, leftStruct, rightStruct, mergedStruct, list.size()));
		list.add(new StructureInfoLine(this, getInfo(leftStruct), getInfo(rightStruct),
			getInfo(mergedStruct), list.size(), "Structure properties"));
		list.add(new StructureInfoLine(this, "{", list.size(), "Syntax"));

		lineBuilder.addComponentLines();

		list.add(new StructureInfoLine(this, "}", list.size(), "Syntax"));
		return list;
	}

	private String getInfo(Structure s) {
		StringBuilder buf = new StringBuilder();
		buf.append("Length = ");
		int length = s.getLength();
		buf.append(length);
		buf.append(" (0x");
		buf.append(Integer.toString(length, 16));
		buf.append("), alignment = ");
		buf.append(s.getAlignment());
		buf.append(", Packed = ");
		buf.append(s.isPackingEnabled());
		return buf.toString();
	}

	public int getSize() {
		return compareLines.size();
	}

	/**
	 * Inner class to build the coordinated component lines (the hard part) of the three structures.
	 */
	private class LineBuilder {
		private List<CoordinatedStructureLine> lines;
		private StructureComponentLine lastComponentLine;
		private DefinedComponentQueue q1 = new DefinedComponentQueue(leftStruct);
		private DefinedComponentQueue q2 = new DefinedComponentQueue(rightStruct);
		private DefinedComponentQueue q3 = new DefinedComponentQueue(mergedStruct);

		LineBuilder(List<CoordinatedStructureLine> lines) {
			this.lines = lines;
		}

		void addComponentLines() {
			int offset = getNextOffset();
			while (offset >= 0) {
				processOffset(offset);
				offset = getNextOffset();
			}
			fillGaps(getMaxSize());
		}

		private int getMaxSize() {
			int size = Math.max(leftStruct.getLength(), rightStruct.getLength());
			return Math.max(size, mergedStruct.getLength());
		}

		private int getNextOffset() {
			int offset1 = q1.nextOffset();
			int offset2 = q2.nextOffset();
			int offset3 = q3.nextOffset();

			int offset = getMinOffset(offset1, offset2);
			return getMinOffset(offset, offset3);
		}

		private int getMinOffset(int offset1, int offset2) {
			if (offset1 < 0) {
				return offset2;
			}
			if (offset2 < 0) {
				return offset1;
			}
			return Math.min(offset1, offset2);
		}

		private void processOffset(int offset) {
			fillGaps(offset);

			if (q1.hasZeroComp(offset) || q2.hasZeroComp(offset) || q3.hasZeroComp(offset)) {
				processZeroLengthComponents(offset);
			}

			if (q1.hasBitField(offset) || q2.hasBitField(offset) || q3.hasBitField(offset)) {
				processBitFields(offset);
			}

			DataTypeComponent comp1 = q1.nextOffset() == offset ? q1.next() : null;
			DataTypeComponent comp2 = q2.nextOffset() == offset ? q2.next() : null;
			DataTypeComponent comp3 = q3.nextOffset() == offset ? q3.next() : null;
			if (CollectionUtils.isAllNull(comp1, comp2, comp3)) {
				return;
			}

			if (comp1 == null) {
				// we already know that a defined component is not there, but this checks for 
				// an undefined at that offset
				comp1 = getUndefinedComp(leftStruct, offset);
			}
			if (comp2 == null) {
				comp2 = getUndefinedComp(rightStruct, offset);
			}
			if (comp3 == null) {
				comp3 = getUndefinedComp(mergedStruct, offset);
			}
			int length = getMaxLength(comp1, comp2, comp3);
			lastComponentLine =
				new StructureComponentLine(CoordinatedStructureModel.this, leftStruct, rightStruct,
					mergedStruct, comp1, comp2, comp3, offset, length, lines.size());
			lines.add(lastComponentLine);
		}

		private void processBitFields(int offset) {
			boolean isFirstBitFieldLine = true;
			DataTypeComponent bitField1 = q1.hasBitField(offset) ? q1.next() : null;
			DataTypeComponent bitField2 = q2.hasBitField(offset) ? q2.next() : null;

			while (bitField1 != null || bitField2 != null) {
				int result = compareBitFields(bitField1, bitField2, offset);
				if (result == 0) {
					addBitFieldLine(bitField1, bitField2, offset, isFirstBitFieldLine);
					bitField1 = q1.hasBitField(offset) ? q1.next() : null;
					bitField2 = q2.hasBitField(offset) ? q2.next() : null;
				}
				else if (result < 0) {
					addBitFieldLine(bitField1, null, offset, isFirstBitFieldLine);
					bitField1 = q1.hasBitField(offset) ? q1.next() : null;
				}
				else {
					addBitFieldLine(null, bitField2, offset, isFirstBitFieldLine);
					bitField2 = q2.hasBitField(offset) ? q2.next() : null;
				}
				isFirstBitFieldLine = false;
			}
		}

		private void addBitFieldLine(DataTypeComponent leftComp, DataTypeComponent rightComp,
				int offset, boolean isFirstBitFieldLineForOffset) {
			DataTypeComponent mergedComp = null;
			DataTypeComponent comp = leftComp != null ? leftComp : rightComp;
			int bitFieldLength1 = leftComp != null ? leftComp.getLength() : 0;
			int bitFieldLength2 = rightComp != null ? rightComp.getLength() : 0;
			int length = Math.max(bitFieldLength1, bitFieldLength2);

			if (q3.hasBitField(offset)) {
				// peek at the next component in the result struct and see if it is a bitfield
				// that matches the entry we are creating
				DataTypeComponent peek = q3.peek();
				if (compareBitFields(comp, peek, offset) == 0) {
					mergedComp = q3.next();
				}
			}

			// If this is the 1st bit field line for an offset, add in undefined components
			// if appropriate for null components
			if (isFirstBitFieldLineForOffset) {
				if (leftComp == null) {
					leftComp = getUndefinedComp(leftStruct, offset);
				}
				if (rightComp == null) {
					rightComp = getUndefinedComp(rightStruct, offset);
				}
				if (mergedComp == null) {
					mergedComp = getUndefinedComp(mergedStruct, offset);
				}
			}
			lastComponentLine =
				new StructureComponentLine(CoordinatedStructureModel.this, leftStruct, rightStruct,
					mergedStruct,
					leftComp, rightComp, mergedComp, offset, length, lines.size());
			lines.add(lastComponentLine);

		}

		private int compareBitFields(DataTypeComponent bitField1, DataTypeComponent bitField2,
				int offset) {
			if (bitField1 == null) {
				return 1;
			}
			if (bitField2 == null) {
				return -1;
			}
			BitFieldDataType bfdt1 = (BitFieldDataType) bitField1.getDataType();
			BitFieldDataType bfdt2 = (BitFieldDataType) bitField2.getDataType();
			int bitStart1 = BitFieldDataType.getNormalizedBitOffset(bfdt1, offset);
			int bitStart2 = BitFieldDataType.getNormalizedBitOffset(bfdt2, offset);

			return bitStart1 - bitStart2;
		}

		private void processZeroLengthComponents(int offset) {
			List<DataTypeComponent> comps1 = getZeroLengthComps(q1, offset);
			List<DataTypeComponent> comps2 = getZeroLengthComps(q2, offset);
			List<DataTypeComponent> comps3 = getZeroLengthComps(q3, offset);

			for (DataTypeComponent comp1 : comps1) {
				DataTypeComponent comp2 = findSameComp(comps2, comp1);
				DataTypeComponent comp3 = findSameComp(comps3, comp1);
				lastComponentLine =
					new StructureComponentLine(CoordinatedStructureModel.this, leftStruct,
						rightStruct, mergedStruct, comp1, comp2, comp3, offset, 0, lines.size());
				lines.add(lastComponentLine);
			}
			for (DataTypeComponent comp2 : comps2) {
				DataTypeComponent comp3 = findSameComp(comps3, comp2);
				lastComponentLine =
					new StructureComponentLine(CoordinatedStructureModel.this, leftStruct,
						rightStruct, mergedStruct, null, comp2, comp3, offset, 0, lines.size());
				lines.add(lastComponentLine);
			}
			for (DataTypeComponent comp3 : comps3) {
				lastComponentLine =
					new StructureComponentLine(CoordinatedStructureModel.this, leftStruct,
						rightStruct, mergedStruct, null, null, comp3, offset, 0, lines.size());
				lines.add(lastComponentLine);
			}

		}

		private DataTypeComponent findSameComp(List<DataTypeComponent> list,
				DataTypeComponent comp) {
			if (list.isEmpty()) {
				return null;
			}
			DataType dataType = comp.getDataType();
			String name = comp.getFieldName();
			Iterator<DataTypeComponent> it = list.iterator();
			while (it.hasNext()) {
				DataTypeComponent next = it.next();
				if (next.getDataType().isEquivalent(dataType) &&
					Objects.equals(name, next.getFieldName())) {
					it.remove();
					return next;
				}
			}
			return null;
		}

		private List<DataTypeComponent> getZeroLengthComps(DefinedComponentQueue q, int offset) {
			if (!q.hasZeroComp(offset)) {
				return Collections.emptyList();
			}
			List<DataTypeComponent> list = new ArrayList<>();
			while (q.hasZeroComp(offset)) {
				list.add(q.next());
			}
			return list;
		}

		private DataTypeComponent getUndefinedComp(Structure struct, int offset) {
			DataTypeComponent comp = struct.getComponentAt(offset);
			if (comp != null && comp.getDataType() == DataType.DEFAULT) {
				return comp;
			}
			return null;
		}

		private int getMaxLength(DataTypeComponent comp1, DataTypeComponent comp2,
				DataTypeComponent comp3) {
			int length = 0;
			if (comp1 != null) {
				length = comp1.getLength();
			}
			if (comp2 != null) {
				length = Math.max(length, comp2.getLength());
			}
			if (comp3 != null) {
				length = Math.max(length, comp3.getLength());
			}
			return length;
		}

		private void fillGaps(int nextOffset) {
			int offset = 0;
			int length = nextOffset;
			if (lastComponentLine != null) {
				offset = lastComponentLine.getOffset() + lastComponentLine.getSize();
				length = nextOffset - offset;
			}
			if (length > 0) {
				DataTypeComponent comp1 = leftStruct.getComponentAt(offset);
				DataTypeComponent comp2 = rightStruct.getComponentAt(offset);
				DataTypeComponent comp3 = mergedStruct.getComponentAt(offset);
				lines.add(
					new StructureComponentLine(CoordinatedStructureModel.this, leftStruct,
						rightStruct,
						mergedStruct, comp1, comp2, comp3, offset, length, lines.size()));
			}
		}

	}

	private class DefinedComponentQueue {
		private DataTypeComponent[] definedComponents;
		private int current = 0;

		DefinedComponentQueue(Structure struct) {
			definedComponents = struct.getDefinedComponents();
		}

		public boolean hasBitField(int offset) {
			if (hasNext()) {
				DataTypeComponent comp = definedComponents[current];
				if (comp.getOffset() == offset && comp.getDataType() instanceof BitFieldDataType) {
					return true;
				}
			}
			return false;
		}

		public boolean hasZeroComp(int offset) {
			if (hasNext()) {
				DataTypeComponent comp = definedComponents[current];
				return comp.getOffset() == offset && comp.getLength() == 0;
			}
			return false;
		}

		public DataTypeComponent next() {
			if (current >= definedComponents.length) {
				return null;
			}
			DataTypeComponent comp = definedComponents[current];
			current++;
			return comp;
		}

		public DataTypeComponent peek() {
			if (current >= definedComponents.length) {
				return null;
			}
			return definedComponents[current];
		}

		public int nextOffset() {
			if (hasNext()) {
				return definedComponents[current].getOffset();
			}
			return -1;
		}

		public boolean hasNext() {
			return current < definedComponents.length;
		}
	}

	public List<CoordinatedStructureLine> getLines() {
		return compareLines;
	}

	public void addChangeListener(Callback callback) {
		changeCallbacks.add(callback);
	}

	public List<ComparisonItem> getData(CompareId compareId) {
		List<ComparisonItem> list = new ArrayList<>();
		for (CoordinatedStructureLine line : compareLines) {
			ComparisonItem item = line.getComparisonItem(compareId);
			if (compareId == CompareId.MERGED && item.isBlank()) {
				// skip blank lines in merged structure display
				continue;
			}
			list.add(item);
		}
		return list;
	}

	public CoordinatedStructureLine getLine(int line) {
		if (line < compareLines.size()) {
			return compareLines.get(line);
		}
		return null;
	}

	void error(String message) {
		errorHandler.accept(message);
	}

	public Structure getMergedStructure() {
		return mergedStruct;
	}

}
