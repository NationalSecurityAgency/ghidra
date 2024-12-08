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
package ghidra.program.model.lang.protorules;

import java.util.ArrayList;

import ghidra.program.model.data.*;
import ghidra.program.model.pcode.PcodeDataTypeManager;

public class PrimitiveExtractor {

	public static class Primitive {
		public DataType dt;		// The primitive data-type
		public int offset;			// Offset within the container

		public Primitive(DataType d, int off) {
			dt = d;
			offset = off;
		}
	}

	private ArrayList<Primitive> primitives;	// List of extracted primitives
	private boolean valid;						// Extraction was invalid
	private boolean aligned;					// True if all primitives are properly aligned
	private boolean unknownElements;			// True if at least one TYPE_UNKNOWN primitive
	private boolean extraSpace;					// True if extra space not attributable to padding
	private boolean unionInvalid;				// True if unions are treated as invalid primitive

	/**
	 * Check that a big Primitive properly overlaps smaller Primitives
	 * 
	 * If the big Primitive does not properly overlap the smaller Primitives starting at the given
	 * point, return -1.  Otherwise, if the big Primitive is floating-point, add the overlapped
	 * primitives to the common refinement list, or if not a floating-point, add the big Primitive
	 * to the list. (Integer primitives are \e preferred over floating-point primitives in this way)
	 * Return the index of the next primitive after the overlap.
	 * @param res holds the common refinement list
	 * @param small is the list of Primitives that are overlapped
	 * @param point is the index of the first overlap
	 * @param big is the big overlapping Primitive
	 * @return the index of the next Primitive after the overlap or -1 if the overlap is invalid
	 */
	private int checkOverlap(ArrayList<Primitive> res, ArrayList<Primitive> small, int point,
			Primitive big) {
		int endOff = big.offset + big.dt.getAlignedLength();
		// If big data-type is a float, let smaller primitives override it, otherwise we keep the big primitive
		boolean useSmall =
			PcodeDataTypeManager.getMetatype(big.dt) == PcodeDataTypeManager.TYPE_FLOAT;
		while (point < small.size()) {
			int curOff = small.get(point).offset;
			if (curOff >= endOff) {
				break;
			}
			curOff += small.get(point).dt.getAlignedLength();
			if (curOff > endOff) {
				return -1;			// Improper overlap of the end of big
			}
			if (useSmall) {
				res.add(small.get(point));
			}
			point += 1;
		}
		if (!useSmall) { 		// If big data-type was preferred
			res.add(big);		// use big Primitive in the refinement
		}
		return point;
	}

	/**
	 * Overwrite first list with common refinement of first and second
	 * 
	 * Given two sets of overlapping Primitives, find a \e common \e refinement of the lists.
	 * If there is any partial overlap of two Primitives, \b false is returned.
	 * If the same primitive data-type occurs at the same offset, it is included in the refinement.
	 * Otherwise an integer data-type is preferred over a floating-point data-type, or a bigger
	 * primitive is preferred over smaller overlapping primitives.
	 * The final refinement replaces the \b first list.
	 * @param first is the first list of Primitives
	 * @param second is the second list
	 * @return true if a refinement was successfully constructed
	 */
	private boolean commonRefinement(ArrayList<Primitive> first, ArrayList<Primitive> second) {
		int firstPoint = 0;
		int secondPoint = 0;
		ArrayList<Primitive> common = new ArrayList<>();
		while (firstPoint < first.size() && secondPoint < second.size()) {
			Primitive firstElement = first.get(firstPoint);
			Primitive secondElement = second.get(secondPoint);
			if (firstElement.offset < secondElement.offset &&
				firstElement.offset + firstElement.dt.getAlignedLength() <= secondElement.offset) {
				common.add(firstElement);
				firstPoint += 1;
				continue;
			}
			if (secondElement.offset < firstElement.offset &&
				secondElement.offset + secondElement.dt.getAlignedLength() <= firstElement.offset) {
				common.add(secondElement);
				secondPoint += 1;
				continue;
			}
			if (firstElement.dt.getAlignedLength() >= secondElement.dt.getAlignedLength()) {
				secondPoint = checkOverlap(common, second, secondPoint, firstElement);
				if (secondPoint < 0) {
					return false;
				}
				firstPoint += 1;
			}
			else {
				firstPoint = checkOverlap(common, first, firstPoint, secondElement);
				if (firstPoint < 0) {
					return false;
				}
				secondPoint += 1;
			}
		}
		// Add any tail primitives from either list
		while (firstPoint < first.size()) {
			common.add(first.get(firstPoint));
			firstPoint += 1;
		}
		while (secondPoint < second.size()) {
			common.add(second.get(secondPoint));
			secondPoint += 1;
		}
		first.clear();
		first.addAll(common);	// Replace first with the refinement
		return true;
	}

	/**
	 * Form a primitive list for each field of the union. Then, if possible, form a common
	 * refinement of all the primitive lists and add to the end of this extractor's list.
	 * @param dt is the union data-type
	 * @param max is the maximum number primitives allowed for \b this extraction
	 * @param offset is the starting offset of the union within the parent
	 * @return true if a common refinement was found and appended
	 */
	private boolean handleUnion(Union dt, int max, int offset) {
		if (unionInvalid) {
			return false;
		}
		int num = dt.getNumComponents();
		if (num == 0) {
			return false;
		}
		DataTypeComponent curField = dt.getComponent(0);

		PrimitiveExtractor common = new PrimitiveExtractor(curField.getDataType(), false,
			offset + curField.getOffset(), max);
		if (!common.isValid()) {
			return false;
		}
		for (int i = 1; i < num; ++i) {
			curField = dt.getComponent(i);

			PrimitiveExtractor next = new PrimitiveExtractor(curField.getDataType(), false,
				offset + curField.getOffset(), max);
			if (!next.isValid()) {
				return false;
			}
			if (!commonRefinement(common.primitives, next.primitives)) {
				return false;
			}
		}
		if (primitives.size() + common.primitives.size() > max) {
			return false;
		}
		for (int i = 0; i < common.primitives.size(); ++i) {
			primitives.add(common.primitives.get(i));
		}
		return true;
	}

	/**
	 * An array of the primitive data-types, with their associated offsets, is constructed.
	 * If the given data-type is already primitive it is put in the array by itself. Otherwise
	 * if it is composite, its components are recursively added to the array.
	 * Boolean properties about the primitives encountered are recorded:
	 *    - Are any of the primitives \b undefined
	 *    - Are all the primitives properly aligned.
	 *       
	 * If a maximum number of extracted primitives is exceeded, or if an illegal
	 * data-type is encountered (\b void or other internal data-type) false is returned.
	 * @param dt is the given data-type to extract primitives from
	 * @param max is the maximum number of primitives to extract before giving up
	 * @param offset is the starting offset to associate with the first primitive
	 * @return true if all primitives were extracted
	 */
	private boolean extract(DataType dt, int max, int offset) {
		if (dt instanceof TypeDef) {
			dt = ((TypeDef) dt).getBaseDataType();
		}
		int metaType = PcodeDataTypeManager.getMetatype(dt);
		switch (metaType) {
			case PcodeDataTypeManager.TYPE_UNKNOWN:
				unknownElements = true;
				// fall-thru
			case PcodeDataTypeManager.TYPE_INT:
			case PcodeDataTypeManager.TYPE_UINT:
			case PcodeDataTypeManager.TYPE_BOOL:
			case PcodeDataTypeManager.TYPE_CODE:
			case PcodeDataTypeManager.TYPE_FLOAT:
			case PcodeDataTypeManager.TYPE_PTR:
			case PcodeDataTypeManager.TYPE_PTRREL:
				if (primitives.size() >= max) {
					return false;
				}
				primitives.add(new Primitive(dt, offset));
				return true;
			case PcodeDataTypeManager.TYPE_ARRAY: {
				int numEls = ((Array) dt).getNumElements();
				DataType base = ((Array) dt).getDataType();
				for (int i = 0; i < numEls; ++i) {
					if (!extract(base, max, offset)) {
						return false;
					}
					offset += base.getAlignedLength();
				}
				return true;
			}
			case PcodeDataTypeManager.TYPE_UNION:
				return handleUnion((Union) dt, max, offset);
			case PcodeDataTypeManager.TYPE_STRUCT:
				break;
			default:
				return false;
		}
		Structure structPtr = (Structure) dt;
		boolean isPacked = structPtr.isPackingEnabled();
		DataTypeComponent[] components = structPtr.getDefinedComponents();
		int expectedOff = offset;
		for (DataTypeComponent component : components) {
			DataType compDT = component.getDataType();
			int curOff = component.getOffset() + offset;
			if (!isPacked) {
				int align = compDT.getAlignment();
				if (curOff % align != 0) {
					aligned = false;
				}
				int rem = expectedOff % align;
				if (rem != 0) {
					expectedOff += (align - rem);
				}
				if (expectedOff != curOff) {
					extraSpace = true;
				}
			}
			if (!extract(compDT, max, curOff)) {
				return false;
			}
			expectedOff = curOff + compDT.getAlignedLength();
		}
		return true;
	}

	/**
	 * @param dt is data-type extract from
	 * @param unionIllegal is true if unions encountered during extraction are considered illegal
	 * @param offset is the starting offset to associate with the data-type
	 * @param max is the maximum number of primitives to extract before giving up
	 */
	public PrimitiveExtractor(DataType dt, boolean unionIllegal, int offset, int max) {
		primitives = new ArrayList<>();
		valid = true;
		aligned = true;
		unknownElements = false;
		extraSpace = false;
		unionInvalid = unionIllegal;
		if (!extract(dt, max, offset)) {
			valid = false;
		}
	}

	/**
	 * @return true if all primitive elements were extracted
	 */
	public boolean isValid() {
		return valid;
	}

	/**
	 * @return true if any extracted element was unknown/undefined
	 */
	public boolean containsUnknown() {
		return unknownElements;
	}

	/**
	 * @return true if all extracted elements are aligned
	 */
	public boolean isAligned() {
		return aligned;
	}

	/**
	 * @return true if there is extra space in the data-type that is not alignment padding
	 */
	public boolean containsHoles() {
		return extraSpace;
	}

	/**
	 * @return the number of primitives extracted
	 */
	public int size() {
		return primitives.size();
	}

	/**
	 * Get the i-th extracted primitive and its offset
	 * @param i is the index
	 * @return the primitive and offset
	 */
	public Primitive get(int i) {
		return primitives.get(i);
	}
}
