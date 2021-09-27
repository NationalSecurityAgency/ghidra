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

import java.util.Comparator;
import java.util.List;

/**
 * The structure interface.
 * <p>
 * NOTE: A zero-length Structure will report a length of 1 which will result in
 * improper code unit sizing since we are unable to support a defined data of length 0.
 * <p>
 * NOTE: The use of zero-length bitfields within non-packed structures is discouraged since they have
 * no real affect and are easily misplaced. Their use should be reserved for packed
 * structures.
 */
public interface Structure extends Composite {

	@Override
	public Structure clone(DataTypeManager dtm);

	/**
	 * Returns the component of this structure with the indicated ordinal.
	 * 
	 * @param ordinal the ordinal of the component requested.
	 * @return the data type component.
	 * @throws IndexOutOfBoundsException if the ordinal is out of bounds
	 */
	@Override
	public DataTypeComponent getComponent(int ordinal) throws IndexOutOfBoundsException;

	/**
	 * Gets the first defined component located at or after the specified offset. 
	 * Note: The returned component may be a zero-length component.
	 * 
	 * @param offset the byte offset into this structure
	 * @return the first defined component located at or after the specified offset or null if not found.
	 */
	public DataTypeComponent getDefinedComponentAtOrAfterOffset(int offset);

	/**
	 * Gets the first non-zero-length component that contains the byte at the specified offset. 
	 * Note that one or more components may share the same offset when a bit-field or zero-length
	 * component is present since these may share an offset.  A null may be returned under one of
	 * the following conditions:
	 * <ul>
	 * <li>offset only corresponds to a zero-length component within a packed structure</li>
	 * <li>offset corresponds to a padding byte within a packed structure</li>
	 * <li>offset is &gt;= structure length.</li>
	 * </ul>
	 * If a bitfield is returned, and the caller supports bitfields, it is recommended that 
	 * {@link #getComponentsContaining(int)} be invoked to gather all bitfields which contain the 
	 * specified offset.
	 * 
	 * @param offset the byte offset into this structure
	 * @return the first non-zero-length component that contains the byte at the specified offset
	 * or null if not found.
	 */
	public DataTypeComponent getComponentContaining(int offset);
	
	/**
	 * Gets the first non-zero-length component that starts at the specified offset. 
	 * Note that one or more components may share the same offset when a bit-field or zero-length
	 * component is present since these may share an offset.  A null may be returned under one of
	 * the following conditions:
	 * <ul>
	 * <li>offset only corresponds to a zero-length component within a packed structure</li>
	 * <li>offset corresponds to a padding byte within a packed structure</li>
	 * <li>offset is contained within a component but is not the starting offset of that component</li>
	 * <li>offset is &gt;= structure length</li>
	 * </ul>
	 * If a bitfield is returned, and the caller supports bitfields, it is recommended that 
	 * {@link #getComponentsContaining(int)} be invoked to gather all bitfields which contain the 
	 * specified offset.
	 * 
	 * @param offset the byte offset into this structure
	 * @return the first component that starts at specified offset or null if not found.
	 */
	public default DataTypeComponent getComponentAt(int offset) {
		DataTypeComponent dtc = getComponentContaining(offset);
		// scan forward with bitfields to find one which starts with offset
		while (dtc != null && dtc.isBitFieldComponent() && dtc.getOffset() < offset &&
			dtc.getOrdinal() < (getNumComponents() - 1)) {
			dtc = getComponent(dtc.getOrdinal() + 1);
		}
		if (dtc != null && dtc.getOffset() == offset) {
			return dtc;
		}
		return null;
	}
	
	/**
	 * Get an ordered list of components that contain the byte at the specified offset.
	 * Unlike {@link #getComponentAt(int)} and {@link #getComponentContaining(int)} this method will
	 * include zero-length components if they exist at the specified offset.  For this reason the
	 * specified offset may equal the structure length to obtain and trailing zero-length components.
	 * Note that this method will only return more than one component when a bit-fields and/or 
	 * zero-length components are present since these may share an offset. An empty list may be 
	 * returned under the following conditions:
	 * <ul>
	 * <li>offset only corresponds to a padding byte within a packed structure</li>
	 * <li>offset is equal structure length and no trailing zero-length components exist</li>
	 * <li>offset is &gt; structure length</li>
	 * </ul>
	 * 
	 * @param offset the byte offset into this structure
	 * @return a list of zero or more components containing the specified offset
	 */
	public List<DataTypeComponent> getComponentsContaining(int offset);

	/**
	 * Returns the lowest-level component that contains the specified offset. This is useful 
	 * for structures that have sub-structures. This method is best used when working with 
	 * known structures which do not contain bitfields or zero-length components since in 
	 * those situations multiple components may correspond to the specified offset.  
	 * A similar ambiguous condition occurs if offset corresponds to a union component.
	 * 
	 * @param offset the byte offset into this data type.
	 * @return a primitive component data type which contains the specified offset.
	 */
	public DataTypeComponent getDataTypeAt(int offset);

	/**
	 * Inserts a new bitfield at the specified ordinal position in this structure. Within packed
	 * structures the specified byteWidth and bitOffset will be ignored since packing will occur at
	 * the specified ordinal position. The resulting component length and bitfield details will
	 * reflect the use of minimal storage sizing.
	 * <p>
	 * For structures with packing disabled, a component shift will only occur if the bitfield placement
	 * conflicts with another component. If no conflict occurs, the bitfield will be placed at the
	 * specified location consuming any DEFAULT components as needed. When a conflict does occur a
	 * shift will be performed at the ordinal position based upon the specified byteWidth. When
	 * located onto existing bitfields they will be packed together provided they do not conflict,
	 * otherwise the conflict rule above applies.
	 * <p>
	 * Supported packing starts with bit-0 (lsb) of the first byte for little-endian, and
	 * with bit-7 (msb) of the first byte for big-endian. This is the default behavior for most
	 * compilers. Insertion behavior may not work as expected if packing rules differ from this.
	 * 
	 * @param ordinal the ordinal of the component to be inserted.
	 * @param byteWidth the storage allocation unit width which contains the bitfield. Must be large
	 *            enough to contain the "effective bit size" and corresponding bitOffset. The actual
	 *            component size used will be recomputed during insertion.
	 * @param bitOffset corresponds to the bitfield left-shift amount with the storage unit when
	 *            viewed as big-endian. The final offset may be reduced based upon the minimal
	 *            storage size determined during insertion.
	 * @param baseDataType the bitfield base datatype (certain restrictions apply).
	 * @param bitSize the declared bitfield size in bits. The effective bit size may be adjusted
	 *            based upon the specified baseDataType.
	 * @param componentName the field name to associate with this component.
	 * @param comment the comment to associate with this component.
	 * @return the bitfield component created whose associated data type will be BitFieldDataType.
	 * @throws InvalidDataTypeException if the specified baseDataType is not a valid base type for
	 *             bitfields.
	 * @throws IndexOutOfBoundsException if ordinal is less than 0 or greater than the current
	 *             number of components.
	 */
	public DataTypeComponent insertBitField(int ordinal, int byteWidth, int bitOffset,
			DataType baseDataType, int bitSize, String componentName, String comment)
			throws InvalidDataTypeException, IndexOutOfBoundsException;

	/**
	 * Inserts a new bitfield at the specified location in this composite. This method is intended
	 * to be used with structures with packing disabled where the bitfield will be precisely placed. Within an
	 * packed structure the specified byteOffset, byteWidth and bitOffset will be used to identify
	 * the appropriate ordinal but may not be preserved. The component length will be computed based
	 * upon the specified parameters and will be reduced from byteWidth to its minimal size for the
	 * new component.
	 * <p>
	 * When packing disabled, a component shift will only occur if the bitfield placement conflicts
	 * with another component. If no conflict occurs, the bitfield will be placed at the specified
	 * location consuming any DEFAULT components as needed. When a conflict does occur a shift will
	 * be performed at the point of conflict based upon the specified byteWidth. When located onto
	 * existing bitfields they will be packed together provided they do not conflict, otherwise the
	 * conflict rule above applies.
	 * <p>
	 * Supported packing for little-endian fills lsb first, whereas big-endian fills msb first.
	 * Insertion behavior may not work as expected if packing rules differ from this.
	 * <p>
	 * 
	 * Zero length bitfields may be inserted although they have no real affect when packing disabled. 
	 * Only the resulting byte offset within the structure is of significance in
	 * determining its ordinal placement.
	 * <p>
	 * 
	 * @param byteOffset the first byte offset within this structure which corresponds to the first
	 *            byte of the specified storage unit identified by its byteWidth.
	 * @param byteWidth the storage unit width which contains the bitfield. Must be large enough to
	 *            contain the specified bitSize and corresponding bitOffset. The actual component
	 *            size used will be recomputed during insertion.
	 * @param bitOffset corresponds to the bitfield left-shift amount with the storage unit when
	 *            viewed as big-endian. The final offset may be reduced based upon the minimal
	 *            storage size determined during insertion.
	 * @param baseDataType the bitfield base datatype (certain restrictions apply).
	 * @param componentName the field name to associate with this component.
	 * @param bitSize the bitfield size in bits. A bitSize of 0 may be specified although its name
	 *            will be ignored.
	 * @param comment the comment to associate with this component.
	 * @return the componentDataType created whose associated data type will be BitFieldDataType.
	 * @throws InvalidDataTypeException if the specified data type is not a valid base type for
	 *             bitfields.
	 */
	public DataTypeComponent insertBitFieldAt(int byteOffset, int byteWidth, int bitOffset,
			DataType baseDataType, int bitSize, String componentName, String comment)
			throws InvalidDataTypeException;

	/**
	 * Inserts a new datatype at the specified offset into this structure. Inserting a component
	 * will cause any conflicting components to shift down to the extent necessary to avoid a
	 * conflict.
	 * 
	 * @param offset the byte offset into the structure where the new datatype is to be inserted.
	 * @param dataType the datatype to insert.  If {@link DataType#DEFAULT} is specified for a packed 
	 * 				structure an {@link Undefined1DataType} will be used in its place.
	 * @param length the length to associate with the dataType. For fixed length types a length
	 *            &lt;= 0 will use the length of the resolved dataType.
	 * @return the componentDataType created.
	 * @throws IllegalArgumentException if the specified data type is not allowed to be inserted
	 *             into this composite data type or an invalid length is specified. For example,
	 *             suppose dt1 contains dt2. Therefore it is not valid to insert dt1 to dt2 since
	 *             this would cause a cyclic dependency.
	 */
	public DataTypeComponent insertAtOffset(int offset, DataType dataType, int length)
			throws IllegalArgumentException;

	/**
	 * Inserts a new datatype at the specified offset into this structure. Inserting a component
	 * will cause any conflicting components to shift down to the extent necessary to avoid a
	 * conflict.
	 * <p>
	 * This method does not support bit-field insertions which must use the method 
	 * {@link #insertBitFieldAt(int, int, int, DataType, int, String, String)}.
	 * 
	 * @param offset the byte offset into the structure where the new datatype is to be inserted.
	 * @param dataType the datatype to insert.  If {@link DataType#DEFAULT} is specified for a packed 
	 * 				structure an {@link Undefined1DataType} will be used in its place.
	 * @param length the length to associate with the dataType. For fixed length types a length
	 *            &lt;= 0 will use the length of the resolved dataType.
	 * @param name the field name to associate with this component.
	 * @param comment the comment to associate with this component.
	 * @return the componentDataType created.
	 * @throws IllegalArgumentException if the specified data type is not allowed to be inserted
	 *             into this composite data type or an invalid length is specified. For example,
	 *             suppose dt1 contains dt2. Therefore it is not valid to insert dt1 to dt2 since
	 *             this would cause a cyclic dependency.
	 */
	public DataTypeComponent insertAtOffset(int offset, DataType dataType, int length, String name,
			String comment) throws IllegalArgumentException;

	/**
	 * Deletes all defined components containing the specified offset in this structure. If the offset
	 * corresponds to a bit-field or zero-length component (e.g., 0-element array) multiple 
	 * components may be deleted.  Bit-fields are only cleared and may leave residual undefined 
	 * components in their place.  This method will generally reduce the length of the structure.
	 * The {@link #clearAtOffset(int)} method should be used for non-packed structures to 
	 * preserve the structure length and placement of other components.
	 * 
	 * @param offset the byte offset into the structure where the component(s) are to be deleted.
	 * An offset equal to the structure length may be specified to delete any trailing zero-length 
	 * components.
	 * 
	 * @throws IllegalArgumentException if a negative offset is specified
	 */
	public void deleteAtOffset(int offset) throws IllegalArgumentException;

	/**
	 * Remove all components from this structure, effectively setting the
	 * length to zero.  Packing and minimum alignment settings are unaffected.
	 */
	public void deleteAll();

	/**
	 * Clears all defined components containing the specified offset in this structure. If the offset
	 * corresponds to a bit-field or zero-length component (e.g., 0-element array) multiple 
	 * components may be cleared.  This method will preserve the structure length and placement 
	 * of other components since freed space will appear as undefined components.
	 * <p>
	 * To avoid clearing zero-length components at a specified offset within a non-packed structure,
	 * the {@link #replaceAtOffset(int, DataType, int, String, String)} may be used with to clear
	 * only the sized component at the offset by specified {@link DataType#DEFAULT} as the replacement
	 * datatype. 
	 * 
	 * @param offset the byte offset into the structure where the component(s) are to be deleted.
	 */
	public void clearAtOffset(int offset);

	/**
	 * Clears the defined component at the specified component ordinal. Clearing a component within
	 * a non-packed structure causes a defined component to be replaced with a number of undefined 
	 * components.  This may not the case when clearing a zero-length component or bit-field 
	 * which may not result in such undefined components.  In the case of a packed structure 
	 * clearing is always completed without backfill. 
	 * 
	 * @param ordinal the ordinal of the component to clear.
	 * @throws IndexOutOfBoundsException if component ordinal is out of bounds
	 */
	public void clearComponent(int ordinal) throws IndexOutOfBoundsException;

	/**
	 * Replaces the component at the specified ordinal with a new component using the 
	 * specified datatype, length, name and comment.  In the case of a packed structure 
	 * a 1-for-1 replacement will occur.  In the case of a non-packed structure certain
	 * restrictions apply:
	 * <ul>
	 * <li>A zero-length component may only be replaced with another zero-length component.</li>
	 * <li>If ordinal corresponds to a bit-field, all bit-fields which overlap the specified 
	 * bit-field will be replaced.</li>
	 * </ul>
	 * There must be sufficient space to complete the replacement factoring in the space freed 
	 * by the consumed component(s).  If there are no remaining defined components beyond the 
	 * consumed components the structure will expand its length as needed. For a packed structure, this 
	 * method behaves the same as a ordinal-based delete followed by an insert.
	 * <p>
	 * Datatypes not permitted include {@link FactoryDataType} types, non-sizable 
	 * {@link Dynamic} types, and those which result in a circular direct dependency.
	 * <p>
	 * NOTE: In general, it is not recommended that this method be used with non-packed 
	 * structures where the replaced component is a bit-field.
	 * 
	 * @param ordinal the ordinal of the component to be replaced.
	 * @param dataType the datatype to insert. If {@link DataType#DEFAULT} is specified for a packed 
	 *             structure an {@link Undefined1DataType} will be used in its place.  If {@link DataType#DEFAULT} 
	 *             is specified for a non-packed structure this is equivelant to {@link #clearComponent(int)}, ignoring
	 *             the length, name and comment arguments.
	 * @param length component length for containing the specified dataType. A positive length is required 
	 *             for sizable {@link Dynamic} datatypes and should be specified as -1 for fixed-length
	 *             datatypes to rely on their resolved size.
	 * @return the new component.
	 * @throws IllegalArgumentException may be caused by: 1) invalid offset specified, 2) invalid datatype or 
	 *             associated length specified, or 3) insufficient space for replacement.
	 * @throws IndexOutOfBoundsException if component ordinal is out of bounds
	 */
	public DataTypeComponent replace(int ordinal, DataType dataType, int length)
			throws IndexOutOfBoundsException, IllegalArgumentException;

	/**
	 * Replaces the component at the specified ordinal with a new component using the 
	 * specified datatype, length, name and comment.  In the case of a packed structure 
	 * a 1-for-1 replacement will occur.  In the case of a non-packed structure certain
	 * restrictions apply:
	 * <ul>
	 * <li>A zero-length component may only be replaced with another zero-length component.</li>
	 * <li>If ordinal corresponds to a bit-field, all bit-fields which overlap the specified 
	 * bit-field will be replaced.</li>
	 * </ul>
	 * There must be sufficient space to complete the replacement factoring in the space freed 
	 * by the consumed component(s).  If there are no remaining defined components beyond the 
	 * consumed components the structure will expand its length as needed. For a packed structure, this 
	 * method behaves the same as a ordinal-based delete followed by an insert.
	 * <p>
	 * Datatypes not permitted include {@link FactoryDataType} types, non-sizable 
	 * {@link Dynamic} types, and those which result in a circular direct dependency.
	 * <p>
	 * NOTE: In general, it is not recommended that this method be used with non-packed 
	 * structures where the replaced component is a bit-field.
	 * 
	 * @param ordinal the ordinal of the component to be replaced.
	 * @param dataType the datatype to insert.  If {@link DataType#DEFAULT} is specified for a packed 
	 *             structure an {@link Undefined1DataType} will be used in its place.  If {@link DataType#DEFAULT} 
	 *             is specified for a non-packed structure this is equivelant to {@link #clearComponent(int)}, ignoring
	 *             the length, name and comment arguments.
	 * @param length component length for containing the specified dataType. A positive length is required 
	 *             for sizable {@link Dynamic} datatypes and should be specified as -1 for fixed-length
	 *             datatypes to rely on their resolved size.
	 * @param name the field name to associate with this component or null.
	 * @param comment the comment to associate with this component or null.
	 * @return the new component.
	 * @throws IllegalArgumentException may be caused by: 1) invalid offset specified, 2) invalid datatype or 
	 *             associated length specified, or 3) insufficient space for replacement.
	 * @throws IndexOutOfBoundsException if component ordinal is out of bounds
	 */
	public DataTypeComponent replace(int ordinal, DataType dataType, int length, String name,
			String comment) throws IndexOutOfBoundsException, IllegalArgumentException;

	/**
	 * Replaces all components containing the specified byte offset with a new component using the 
	 * specified datatype, length, name and comment. If the offset corresponds to a bit-field 
	 * more than one component may be consumed by this replacement.  
	 * <p>
	 * This method may not be used to replace a zero-length component since there may be any number 
	 * of zero-length components at the same offset. If the only defined component(s) at the specified
	 * offset are zero-length the subsequent undefined will be replaced in the case of a non-packed 
	 * structure.  For a packed structure such a case would be treated as an insert as would an offset 
	 * which is not contained within a component.  
	 * <p>
	 * For a non-packed structure a replacement will attempt to consume sufficient
	 * space within moving other defined components.  There must be sufficient space to complete 
	 * the replacement factoring in the space freed by the consumed component(s).  When replacing the 
	 * last defined component the structure size will be expanded as needed to fit the new component.
	 * For a packed If there are no remaining defined components beyond 
	 * the consumed components, or an offset equals to the structure length is specified, the
	 * structure will expand its length as needed. 
	 * <p>
	 * For a non-packed structure the new component will use the specified offset.  In the case of 
	 * packed structure, the actual offset will be determined during a repack.
	 * <p>
	 * Datatypes not permitted include {@link FactoryDataType} types, non-sizable 
	 * {@link Dynamic} types, and those which result in a circular direct dependency.
	 * 
	 * @param offset the byte offset into the structure where the datatype is to be placed.  The specified
	 *             offset must be less than the length of the structure. 
	 * @param dataType the datatype to insert.  If {@link DataType#DEFAULT} is specified for a packed 
	 * 			   structure an {@link Undefined1DataType} will be used in its place.  If {@link DataType#DEFAULT} 
	 *             is specified for a non-packed structure this is equivelant to clearing all components, 
	 *             which contain the specified offset, ignoring the length, name and comment arguments.
	 * @param length component length for containing the specified dataType. A positive length is required 
	 *             for sizable {@link Dynamic} datatypes and should be specified as -1 for fixed-length
	 *             datatypes to rely on their resolved size.
	 * @param name the field name to associate with this component or null.
	 * @param comment the comment to associate with this component or null.
	 * @return the new component.
	 * @throws IllegalArgumentException may be caused by: 1) invalid offset specified, 2) invalid datatype or 
	 *             associated length specified, or 3) insufficient space for replacement.
	 */
	public DataTypeComponent replaceAtOffset(int offset, DataType dataType, int length, String name,
			String comment) throws IllegalArgumentException;

	/**
	 * Increases the size of the structure by the specified amount by adding undefined filler at the
	 * end of the structure.  NOTE: This method only has an affect on non-packed structures.
	 * 
	 * @param amount the amount by which to grow the structure.
	 * @throws IllegalArgumentException if amount &lt; 1
	 */
	public void growStructure(int amount);

	/**
	 * <code>BitOffsetComparator</code> provides ability to compare an normalized bit offset (see
	 * {@link #getNormalizedBitfieldOffset(int, int, int, int, boolean)}) with a
	 * {@link DataTypeComponent} object. The offset will be considered equal (0) if the component
	 * contains the offset. A normalized component bit numbering is used to establish the footprint
	 * of each component with an ordinal-based ordering (assumes specific LE/BE allocation rules).
	 * Bit offsets for this comparator number the first allocated bit of the structure as 0 and the
	 * last allocated bit of the structure as (8 * structLength) - 1. For big-endian bitfields the
	 * msb of the bitfield will be assigned the lower bit-number (assumes msb-allocated-first),
	 * while little-endian will perform similar numbering assuming byte-swap and bit-reversal of the
	 * storage unit (assumes lsb-allocated-first). Both cases result in a normalized view where
	 * normalized bit-0 is allocated first.
	 * 
	 * <pre>
	 * {@literal
	 * Example:
	 *    
	 * Big-Endian (normalized view):
	 *    | . . . . . . . 7 | 8 9 . . . . . . |
	 *    |<--------------------------------->| storage-size (2-bytes)
	 *                        |<--------------| bit-offset (6, lsb position within storage unit)
	 *                    |<--->|               bit-size (3)
	 *                        
	 * Little-Endian (normalized view, w/ storage byte-swap and bit-reversal):
	 *    | . . . . . . 6 7 | 8 . . . . . . . |
	 *    |------------>|                       bit-offset (6, lsb position within storage unit)
	 *                  |<--->|                 bit-size (3)
	 * }
	 * </pre>
	 */
	public static class BitOffsetComparator implements Comparator<Object> {

		public static final Comparator<Object> INSTANCE_LE = new BitOffsetComparator(false);
		public static final Comparator<Object> INSTANCE_BE = new BitOffsetComparator(true);

		private boolean bigEndian;

		public BitOffsetComparator(boolean bigEndian) {
			this.bigEndian = bigEndian;
		}

		@Override
		public int compare(Object o1, Object o2) {
			if (o1 instanceof Integer) {
				return -compare(o2, o1);
			}
			DataTypeComponent dtc = (DataTypeComponent) o1;
			int bitOffset = ((Integer) o2).intValue();

			int startBit, endBit;
			if (dtc.isBitFieldComponent()) {
				BitFieldDataType bitfield = (BitFieldDataType) dtc.getDataType();
				startBit = getNormalizedBitfieldOffset(dtc.getOffset(), dtc.getLength(),
					bitfield.getBitSize(), bitfield.getBitOffset(), bigEndian);
				endBit = startBit + bitfield.getBitSize() - 1;
			}
			else {
				startBit = 8 * dtc.getOffset();
				endBit = startBit + (8 * dtc.getLength()) - 1;
			}

			if (bitOffset < startBit) {
				return 1;
			}
			if (bitOffset > endBit) {
				return -1;
			}
			return 0;
		}

		/**
		 * Compute the normalized bit offset of a bitfield relative to the start of a structure.
		 * 
		 * NOTE: This implementation currently relies only on endianess to dictate bit allocation
		 * ordering. If future support is added for alternate bitfield packing, this implementation
		 * will require modification.
		 * 
		 * @param byteOffset byte offset within structure of storage unit
		 * @param storageSize storage unit size (i.e., component length)
		 * @param effectiveBitSize size of bitfield in bits
		 * @param bitOffset left shift amount for bitfield based upon a big-endian view of the
		 *            storage unit
		 * @param bigEndian true if big-endian packing applies
		 * @return normalized bit-offset
		 */
		public static int getNormalizedBitfieldOffset(int byteOffset, int storageSize,
				int effectiveBitSize, int bitOffset, boolean bigEndian) {
			int offset = (8 * byteOffset);
			if (effectiveBitSize == 0) {
				// force zero-length bitfield placement
				effectiveBitSize = 1;
				if (bigEndian) {
					bitOffset |= 7;
				}
				else {
					bitOffset &= 0xfffffff8;
				}
			}
			if (bigEndian) {
				offset += (8 * storageSize) - effectiveBitSize - bitOffset;
			}
			else {
				offset += bitOffset;
			}
			return offset;
		}

	}

}
