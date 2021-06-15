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
 * Interface for common methods in Structure and Union
 */
public interface CompositeInternal extends Composite {

	/**
	 * The stored packing value which corresponds to a composite that will automatically pack 
	 * based upon the alignment requirements of its components.  A positive pack value will
	 * also pack in a similar fashion but will use the pack value as a maximum alignment
	 * for each component.
	 * See {@link #getStoredPackingValue}.
	 */
	public final static int DEFAULT_PACKING = 0;

	/**
	 * The stored packing value which corresponds to a composite whoose packing has been disabled.
	 * In the case of structures this will permit explicit component placement by
	 * offset within the structure and undefined filler components will be used.
	 * This is the initial state of all newly instantiated structures.
	 * See {@link #getStoredPackingValue()}.
	 */
	public final static int NO_PACKING = -1;

	/**
	 * The stored minimum alignment value which indicates the default alignment 
	 * should be used based upon the packing and component alignment requirements.
	 * See {@link #getStoredMinimumAlignment}.
	 */
	public final static int DEFAULT_ALIGNMENT = 0;

	/**
	 * The stored minimum alignment value which indicates the machine alignment 
	 * should be used as the minimum alignment (as defined by the current 
	 * {@link DataOrganization#getMachineAlignment()}).
	 * See {@link #getStoredMinimumAlignment()}.
	 */
	public final static int MACHINE_ALIGNMENT = -1;

	/**
	 * Gets the current packing value (typically a power of 2).  Other special values 
	 * which may be returned include {@value #DEFAULT_PACKING} and {@value #NO_PACKING}. 
	 * @return the current positive packing value, {@value #DEFAULT_PACKING} or {@value #NO_PACKING}.
	 */
	public int getStoredPackingValue();

	/**
	 * Sets the current packing behavior (positive value, usually a power of 2). If a positive 
	 * value is specified the use of packing will be enabled if it was previously disabled
	 * (see {@link #setPackingEnabled(boolean)}.  A positive value will set the maximum
	 * alignment for this composite and each component within a structure 
	 * (e.g., a value of 1 will eliminate any padding).
	 * <br>
	 * Special packing values which may be specified include:
	 * <ul>
	 * <li>{@value #DEFAULT_PACKING} will perform default packing based upon the alignment
	 * requirements of the individual components.</li>
	 *  <li>{@link #NO_PACKING} (or any negative value) will disable packing</li>
	 * </ul>
	 * @param packingValue the new positive packing value, or {@value #DEFAULT_PACKING} or
	 * {@link #NO_PACKING}. A negative value will be treated the same as {@link #NO_PACKING}.
	 */
//	public void setStoredPackingValue(int packingValue);

	/**
	 * Get the minimum alignment setting for this Composite which contributes 
	 * to the actual computed alignment value (see {@link #getAlignment()}.
	 * @return the minimum alignment setting for this Composite or a reserved value to indicate 
	 * either {@link #DEFAULT_ALIGNMENT} or {@link #MACHINE_ALIGNMENT}.
	 */
	public int getStoredMinimumAlignment();

	/**
	 * <code>ComponentComparator</code> provides ability to compare two DataTypeComponent objects
	 * based upon their ordinal. Intended to be used to sort components based upon ordinal.
	 */
	public static class ComponentComparator implements Comparator<DataTypeComponent> {

		public static final ComponentComparator INSTANCE = new ComponentComparator();

		@Override
		public int compare(DataTypeComponent dtc1, DataTypeComponent dtc2) {
			return dtc1.getOrdinal() - dtc2.getOrdinal();
		}
	}

	/**
	 * <code>OffsetComparator</code> provides ability to compare an Integer offset with a
	 * DataTypeComponent object. The offset will be consider equal (0) if the component contains the
	 * offset.
	 */
	public static class OffsetComparator implements Comparator<Object> {

		public static final OffsetComparator INSTANCE = new OffsetComparator();

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
	 * <code>OrdinalComparator</code> provides ability to compare an Integer ordinal with a
	 * DataTypeComponent object. The ordinal will be consider equal (0) if the component corresponds
	 * to the specified ordinal.
	 * <p>
	 */
	public static class OrdinalComparator implements Comparator<Object> {

		public static final OrdinalComparator INSTANCE = new OrdinalComparator();

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
