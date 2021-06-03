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

import java.util.Iterator;
import java.util.List;

/**
 * <code>AlignedStructurePacker</code> provides support for performing aligned packing
 * of Structure components.
 * <p>
 * NOTE: We currently have no way of conveying or supporting explicit bitfield component pragmas 
 * supported by some compilers (e.g., bit_field_size, bit_field_align, bit_packing).
 */
public class AlignedStructurePacker {

	private final StructureInternal structure;
	private final List<? extends InternalDataTypeComponent> components;

	private final DataOrganization dataOrganization;

	/**
	 * Constructor.
	 * @param structure structure whose components need to be packed and updated
	 * during packing (ordinal, offset, length and bit-field datatypes may be modified)
	 * @param components list of mutable component
	 */
	protected AlignedStructurePacker(StructureInternal structure,
			List<? extends InternalDataTypeComponent> components) {
		this.structure = structure;
		this.components = components;
		dataOrganization = structure.getDataOrganization();
	}

	/**
	 * <code>StructurePackResult</code> provides access to aligned
	 * packing results
	 */
	public static class StructurePackResult {
		public final int numComponents;
		public final int structureLength;
		public final int alignment;
		public final boolean componentsChanged;

		StructurePackResult(int numComponents, int structureLength, int alignment,
				boolean componentsChanged) {
			this.numComponents = numComponents;
			this.structureLength = structureLength;
			this.alignment = alignment;
			this.componentsChanged = componentsChanged;
		}
	}

	/**
	 * Perform packing on the structure components.
	 * @return pack result data
	 */
	protected StructurePackResult pack() {

		boolean componentsChanged = false;

		int componentCount = 0;

		AlignedComponentPacker packer =
			new AlignedComponentPacker(structure.getStoredPackingValue(), dataOrganization);

		// Remove any default components from list
		Iterator<? extends InternalDataTypeComponent> componentIterator = components.iterator();
		while (componentIterator.hasNext()) {
			InternalDataTypeComponent dataTypeComponent = componentIterator.next();
			DataType componentDt = dataTypeComponent.getDataType();
			if (DataType.DEFAULT == componentDt) {
				componentIterator.remove(); // remove default components.
				componentsChanged = true;
			}
			++componentCount;
		}

		int index = 0;
		for (InternalDataTypeComponent dataTypeComponent : components) {
			boolean isLastComponent = (++index == componentCount);
			packer.addComponent(dataTypeComponent, isLastComponent);
		}

		int defaultAlignment = packer.getDefaultAlignment();

		int length = packer.getLength();
		componentsChanged |= packer.componentsChanged();

		DataTypeComponent flexibleArrayComponent = structure.getFlexibleArrayComponent();
		if (flexibleArrayComponent != null) {
			// account for flexible array type and any end of structure padding required
			int componentAlignment = CompositeAlignmentHelper.getPackedAlignment(dataOrganization,
				structure.getStoredPackingValue(), flexibleArrayComponent);
			length = DataOrganizationImpl.getAlignedOffset(componentAlignment, length);
			defaultAlignment =
				DataOrganizationImpl.getLeastCommonMultiple(defaultAlignment, componentAlignment);
		}

		int alignment = defaultAlignment;
		AlignmentType alignmentType = structure.getAlignmentType();
		if (alignmentType != AlignmentType.DEFAULT) {
			// Apply minimum alignment if applicable - may be reduced by explicit pack
			// Simplified logic assumes pack and align values which are a power of 2 (1,2,4,8,16...)
			int minAlign =
				alignmentType == AlignmentType.MACHINE ? dataOrganization.getMachineAlignment()
						: structure.getExplicitMinimumAlignment();
			alignment = Math.max(defaultAlignment, minAlign);
		}

		if (length != 0) {
			length = DataOrganizationImpl.getAlignedOffset(alignment, length);
		}

		return new StructurePackResult(componentCount, length, alignment, componentsChanged);
	}

	/**
	 * Perform structure component packing.  Specified components may be updated to reflect 
	 * packing (ordinal, offset, length and bit-field datatypes may be modified).  The caller 
	 * is responsible for updating structure length and component count based upon
	 * returned result.  Component count is should only change if component
	 * list includes DEFAULT members which will be ignored.
	 * @param structure structure whose members are to be aligned/packed.
	 * @param components structure components (excludes any trailing flexible array).
	 * @return aligned packing result
	 */
	public static StructurePackResult packComponents(StructureInternal structure,
			List<? extends InternalDataTypeComponent> components) {
		AlignedStructurePacker packer = new AlignedStructurePacker(structure, components);
		return packer.pack();
	}

}
