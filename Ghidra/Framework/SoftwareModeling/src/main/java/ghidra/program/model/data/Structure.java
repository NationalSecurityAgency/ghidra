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

/**
 * The structure interface.
 * <p>
 * NOTE: Structures containing only a flexible array will report a length of 1
 * which will result in improper code unit sizing since we are unable to support a 
 * defined data of length 0.
 * <p>
 * NOTE: The use of zero-length bitfields within unaligned structures is discouraged since
 * they have no real affect and are easily misplaced.  Their use should be reserved for 
 * aligned/packed structures.
 */
public interface Structure extends Composite {

	/**
	 * Returns the component of this structure with the indicated ordinal.
	 * If the specified ordinal equals {@link #getNumComponents()} the defined 
	 * flexible array component will be returned, otherwise an out of bounds
	 * exception will be thrown. Use of {@link #getFlexibleArrayComponent()} is preferred 
	 * for obtaining this special trailing component.
	 * @param ordinal the component's ordinal (zero based).
	 * @return the data type component.
	 * @throws ArrayIndexOutOfBoundsException if the ordinal is out of bounds
	 */
	@Override
	public abstract DataTypeComponent getComponent(int ordinal);

	/**
	 * Gets the immediate child component that contains the byte
	 * at the given offset.  If the specified offset corresponds to 
	 * a bit-field,the first bit-field component containing the offset
	 * will be returned.
	 * @param offset the byte offset into this data type
	 * @return the immediate child component.
	 */
	public abstract DataTypeComponent getComponentAt(int offset);

	/**
	 * Returns the primitive Data Type that is at this offset.  This is useful
	 * for prototypes that have components that are made up of other components
	 * If the specified offset corresponds to 
	 * a bit-field,the BitFieldDataType of the first bit-field component containing 
	 * the offset will be returned.
	 * @param offset the byte offset into this data type.
	 * @return the primitive data type at the offset.
	 */
	public abstract DataTypeComponent getDataTypeAt(int offset);

	/**
	 * Inserts a new bitfield at the specified ordinal position in this structure. 
	 * Within aligned structures the specified byteWidth and bitOffset will be 
	 * ignored since packing will occur at the specified ordinal position.
	 * The resulting component length and bitfield details will reflect the use
	 * of minimal storage sizing.
	 * <p>
	 * For unaligned structures, a component shift will only occur if the bitfield placement 
	 * conflicts with another component.  If no conflict occurs, the bitfield will be placed 
	 * at the specified location consuming any DEFAULT components as needed.  When a conflict 
	 * does occur a shift will be performed at the ordinal position based upon the specified 
	 * byteWidth.  When located onto existing bitfields they will be packed together 
	 * provided they do not conflict, otherwise the conflict rule above applies.
	 * <p>
	 * Supported aligned packing starts with bit-0 (lsb) of the first byte for little-endian, and 
	 * with bit-7 (msb) of the first byte for big-endian.  This is the default behavior for most
	 * compilers.  Insertion behavior may not work as expected if packing rules differ from this.
	 * @param ordinal the ordinal where the new datatype is to be inserted.
	 * @param byteWidth the storage allocation unit width which contains the bitfield.  Must be large
	 * enough to contain the "effective bit size" and corresponding bitOffset.  The actual 
	 * component size used will be recomputed during insertion.
	 * @param bitOffset corresponds to the bitfield left-shift amount with the storage 
	 * unit when viewed as big-endian.  The final offset may be reduced based upon
	 * the minimal storage size determined during insertion.  
	 * @param baseDataType the bitfield base datatype (certain restrictions apply).
	 * @param bitSize the declared bitfield size in bits.  The effective bit size may be
	 * adjusted based upon the specified baseDataType.
	 * @param componentName the field name to associate with this component.
	 * @param comment the comment to associate with this component.
	 * @return the bitfield component created whose associated data type will
	 * be BitFieldDataType.
	 * @throws InvalidDataTypeException if the specified baseDataType is
	 * not a valid base type for bitfields.
	 * @throws ArrayIndexOutOfBoundsException if ordinal is less than 0 or greater than the 
	 * current number of components.
	 */
	public DataTypeComponent insertBitField(int ordinal, int byteWidth, int bitOffset,
			DataType baseDataType, int bitSize, String componentName, String comment)
			throws InvalidDataTypeException, ArrayIndexOutOfBoundsException;

	/**
	 * Inserts a new bitfield at the specified location in this composite.  
	 * This method is intended to be used with unaligned structures where 
	 * the bitfield will be precisely placed.  Within an aligned structure the specified
	 * byteOffset, byteWidth and bitOffset will be used to identify the appropriate ordinal
	 * but may not be preserved. The component length will be computed 
	 * based upon the specified parameters and will be reduced from byteWidth to 
	 * its minimal size for the new component.
	 * <p>
	 * For unaligned mode, a component shift will only occur if the bitfield placement 
	 * conflicts with another component.  If no conflict occurs, the bitfield will be placed 
	 * at the specified location consuming any DEFAULT components as needed.  When a conflict 
	 * does occur a shift will be performed at the point of conflict based upon the specified 
	 * byteWidth.  When located onto existing bitfields they will be packed together 
	 * provided they do not conflict, otherwise the conflict rule above applies.
	 * <p>
	 * Supported packing for little-endian fills lsb first, whereas big-endian fills msb first.
	 * Insertion behavior may not work as expected if packing rules differ from this.
	 * <p>
	 * Zero length bitfields may be inserted although they have no real affect for 
	 * unaligned structures.  Only the resulting byte offset within the structure 
	 * is of significance in determining its ordinal placement.
	 * <p> 
	 * @param byteOffset the first byte offset within this structure which corresponds to the
	 * first byte of the specified storage unit identified by its byteWidth.
	 * @param byteWidth the storage unit width which contains the bitfield.  Must be large
	 * enough to contain the specified bitSize and corresponding bitOffset.  The actual 
	 * component size used will be recomputed during insertion.
	 * @param bitOffset corresponds to the bitfield left-shift amount with the storage 
	 * unit when viewed as big-endian.  The final offset may be reduced based upon
	 * the minimal storage size determined during insertion. 
	 * @param baseDataType the bitfield base datatype (certain restrictions apply).
	 * @param componentName the field name to associate with this component.
	 * @param bitSize the bitfield size in bits.  A bitSize of 0 may be specified 
	 * although its name will be ignored.
	 * @param comment the comment to associate with this component.
	 * @return the componentDataType created whose associated data type will
	 * be BitFieldDataType.
	 * @throws InvalidDataTypeException if the specified data type is
	 * not a valid base type for bitfields.
	 */
	public DataTypeComponent insertBitFieldAt(int byteOffset, int byteWidth, int bitOffset,
			DataType baseDataType, int bitSize, String componentName, String comment)
			throws InvalidDataTypeException;

	/**
	 * Inserts a new datatype at the specified offset into this structure.  
	 * Inserting a component will causing any conflicting component
	 * to shift down to the extent necessary to avoid a conflict.
	 * @param offset the byte offset into the structure where the new datatype is to be inserted.	
	 * @param dataType the datatype to insert.
	 * @param length the length to associate with the dataType.
	 * For fixed length types a length &lt;= 0 will use the length of the resolved dataType.
	 * @return the componentDataType created.
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to be inserted into this composite data type or an invalid length
	 * is specified.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to insert dt1 to dt2 since this would cause a cyclic dependency.
	 */
	public DataTypeComponent insertAtOffset(int offset, DataType dataType, int length)
			throws IllegalArgumentException;

	/**
	 * Inserts a new datatype at the specified offset into this structure.
	 * Inserting a component will causing any conflicting component
	 * to shift down to the extent necessary to avoid a conflict.
	 * @param offset the byte offset into the structure where the new datatype is to be inserted.	
	 * @param dataType the datatype to insert.
	 * @param length the length to associate with the dataType.
	 * For fixed length types a length &lt;= 0 will use the length of the resolved dataType.
	 * @param name the field name to associate with this component.
	 * @param comment the comment to associate with this component.
	 * @return the componentDataType created.
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to be inserted into this composite data type or an invalid length is specified.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to insert dt1 to dt2 since this would cause a cyclic dependency.
	 */
	public DataTypeComponent insertAtOffset(int offset, DataType dataType, int length, String name,
			String comment) throws IllegalArgumentException;

	/**
	 * Deletes the component containing the specified offset in this structure.  If the offset
	 * corresponds to a bit-field, all bit-fields whose base type group contains the offset will 
	 * be removed.
	 * @param offset the byte offset into the structure where the datatype is to be deleted.	
	 */
	public void deleteAtOffset(int offset);

	/**
	 * Remove all components from this structure (including flex-array), 
	 * effectively setting the length to zero.
	 */
	public void deleteAll();

	/**
	 * Clears the defined component at the given component index.  Clearing a 
	 * component causes a defined component to be replaced with a number of
	 * undefined dataTypes to offset the removal of the defined dataType.
	 * @param index the index of the component to clear.
	 * @throws ArrayIndexOutOfBoundsException if component ordinal is out of bounds
	 */
	public void clearComponent(int index) throws ArrayIndexOutOfBoundsException;

	/**
	 * Replaces the component at the given component index with a new component
	 * of the indicated data type.
	 * @param index the index where the datatype is to be replaced.	
	 * @param dataType the datatype to insert.
	 * @param length the length of the dataType to insert.
	 * For fixed length types a length &lt;= 0 will use the length of the resolved dataType.
	 * @return the new componentDataType at the index.
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to replace a component in this composite data type or an invalid
	 * length is specified.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to replace a dt2 component with dt1 since this would cause a cyclic 
	 * dependency.  In addition, any attempt to replace an existing bit-field
	 * component or specify a {@link BitFieldDataType} will produce this error.
	 * @throws ArrayIndexOutOfBoundsException if component index is out of bounds
	 */
	public DataTypeComponent replace(int index, DataType dataType, int length)
			throws ArrayIndexOutOfBoundsException, IllegalArgumentException;

	/**
	 * Replaces the component at the given component index with a new component
	 * of the indicated data type.
	 * @param index the index where the datatype is to be replaced.	
	 * @param dataType the datatype to insert.
	 * @param length the length to associate with the dataType.
	 * For fixed length types a length &lt;= 0 will use the length of the resolved dataType.
	 * @param name the field name to associate with this component.
	 * @param comment the comment to associate with this component.
	 * @return the new componentDataType at the index.
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to replace a component in this composite data type or an invalid
	 * length is specified.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to replace a dt2 component with dt1 since this would cause a cyclic 
	 * dependency.  In addition, any attempt to replace an existing bit-field
	 * component or specify a {@link BitFieldDataType} will produce this error.
	 * @throws ArrayIndexOutOfBoundsException if component index is out of bounds
	 */
	public DataTypeComponent replace(int index, DataType dataType, int length, String name,
			String comment) throws ArrayIndexOutOfBoundsException, IllegalArgumentException;

	/**
	 * Replaces the component at the specified byte offset with a new component
	 * of the indicated data type.   If the offset corresponds to a bit-field, all bit-fields 
	 * at that offset will be removed and replaced by the specified component.  Keep in mind
	 * bit-field or any component removal must clear sufficient space for an unaligned 
	 * structure to complete the replacement.
	 * @param offset the byte offset into the structure where the datatype is 
	 * to be replaced.	
	 * @param dataType the datatype to insert.
	 * @param length the length to associate with the dataType.
	 * For fixed length types a length &lt;= 0 will use the length of the resolved dataType.
	 * @param name the field name to associate with this component.
	 * @param comment the comment to associate with this component.
	 * @return the new componentDataType at the index.
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to replace a component in this composite data type or an invalid 
	 * length is specified.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to replace a dt2 component with dt1 since this would cause a cyclic 
	 * dependency.  In addition, any attempt to replace an existing bit-field
	 * component or specify a {@link BitFieldDataType} will produce this error.
	 */
	public DataTypeComponent replaceAtOffset(int offset, DataType dataType, int length, String name,
			String comment) throws IllegalArgumentException;

	/**
	 * Determine if a trailing flexible array component has been defined.
	 * @return true if trailing flexible array component has been defined.
	 */
	public boolean hasFlexibleArrayComponent();

	/**
	 * Get the optional trailing flexible array component associated with this structure.
	 * @return optional trailing flexible array component associated with this structure or null
	 * if not present.
	 */
	public DataTypeComponent getFlexibleArrayComponent();

	/**
	 * Set the optional trailing flexible array component associated with this structure.
	 * @param flexType the flexible array dataType (example: for 'char[0]' the type 'char' should be specified)
	 * @param name component field name or null for default name
	 * @param comment component comment
	 * @return updated flexible array component
	 * @throws IllegalArgumentException if specified flexType is not permitted (e.g., 
	 * self referencing or unsupported type)
	 */
	public DataTypeComponent setFlexibleArrayComponent(DataType flexType, String name,
			String comment) throws IllegalArgumentException;

	/**
	 * Remove the optional trailing flexible array component associated with this structure.
	 */
	public void clearFlexibleArrayComponent();

	/**
	 * Increases the size of the structure by the given amount by adding undefined datatypes
	 * at the end of the structure.
	 * @param amount the amount by which to grow the structure.
	 * @throws IllegalArgumentException if amount &lt; 1
	 */
	public void growStructure(int amount);

	/**
	 * Sets the current packing value (usually a power of 2). A value of NOT_PACKING should be passed 
	 * if this isn't a packed data type. Otherwise this value indicates a maximum alignment
	 * for any component within this data type. Calling this method will cause the data type to
	 * become an internally aligned data type.
	 * (Same as {@link Composite#setPackingValue(int)})
	 * @param maxAlignment the new packing value or 0 for NOT_PACKING.
	 * A negative value will be treated the same as 0.
	 */
	public void pack(int maxAlignment);

	/**
	 * <code>BitOffsetComparator</code> provides ability to compare an normalized bit offset
	 * (see {@link #getNormalizedBitfieldOffset(int, int, int, int, boolean)}) with a
	 * {@link DataTypeComponent} object.  The offset will be considered equal (0) if the component 
	 * contains the offset.  A normalized component bit numbering is used to establish the footprint
	 * of each component with an ordinal-based ordering (assumes specific LE/BE allocation rules).  
	 * Bit offsets for this comparator number the first allocated bit of the structure as 0 and the
	 * last allocated bit of the structure as (8 * structLength) - 1.  For big-endian bitfields
	 * the msb of the bitfield will be assigned the lower bit-number (assumes msb-allocated-first), 
	 * while little-endian will perform similar numbering assuming byte-swap and bit-reversal of the 
	 * storage unit (assumes lsb-allocated-first).  Both cases result in a normalized view where 
	 * normalized bit-0 is allocated first.
	 * 
	 * <pre>{@literal
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
	 * }</pre>
	 */
	public static class BitOffsetComparator implements Comparator<Object> {

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
		 * ordering.  If future support is added for alternate bitfield packing, this implementation will
		 * require modification.
		 * 
		 * @param byteOffset byte offset within structure of storage unit
		 * @param storageSize storage unit size (i.e., component length)
		 * @param effectiveBitSize size of bitfield in bits
		 * @param bitOffset left shift amount for bitfield based upon a big-endian view of the
		 * storage unit
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

	/**
	 * <code>OffsetComparator</code> provides ability to compare an Integer offset
	 * with a DataTypeComponent object.  The offset will be consider equal (0) if
	 * the component contains the offset.
	 */
	public static class OffsetComparator implements Comparator<Object> {

		@Override
		public int compare(Object o1, Object o2) {
			if (o1 instanceof Integer) {
				return -compare(o2, o1);
			}
			DataTypeComponent dtc = (DataTypeComponent) o1;
			int offset = ((Integer) o2).intValue();
			if (offset < dtc.getOffset()) {
				return 1;
			}
			else if (offset > dtc.getEndOffset()) {
				return -1;
			}
			return 0;
		}

	}

	/**
	 * <code>OrdinalComparator</code> provides ability to compare an Integer ordinal
	 * with a DataTypeComponent object.  The offset will be consider equal (0) if
	 * the component corresponds to the specified ordinal.
	 */
	public static class OrdinalComparator implements Comparator<Object> {

		@Override
		public int compare(Object o1, Object o2) {
			if (o1 instanceof Integer) {
				return -compare(o2, o1);
			}
			DataTypeComponent dtc = (DataTypeComponent) o1;
			int ordinal = ((Integer) o2).intValue();
			return dtc.getOrdinal() - ordinal;
		}

	}
}
