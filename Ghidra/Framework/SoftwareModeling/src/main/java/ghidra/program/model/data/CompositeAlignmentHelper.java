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

public class CompositeAlignmentHelper {

	private static int getCompositeAlignmentMultiple(DataOrganization dataOrganization,
			Composite composite) {
		int allComponentsLCM = 1;
		int packingAlignment = composite.getPackingValue();

		DataTypeComponent[] dataTypeComponents = composite.getDefinedComponents();
		for (DataTypeComponent dataTypeComponent : dataTypeComponents) {
			int impartedAlignment = CompositeAlignmentHelper.getPackedAlignment(dataOrganization,
				packingAlignment, dataTypeComponent);
			if (impartedAlignment != 0) {
				allComponentsLCM = DataOrganizationImpl.getLeastCommonMultiple(allComponentsLCM,
					impartedAlignment);
			}
		}
		if (composite instanceof Structure) {
			Structure struct = (Structure) composite;
			DataTypeComponent flexibleArrayComponent = struct.getFlexibleArrayComponent();
			if (flexibleArrayComponent != null) {
				allComponentsLCM = getComponentAlignmentLCM(dataOrganization, allComponentsLCM,
					packingAlignment, flexibleArrayComponent);
			}
		}
		return allComponentsLCM;
	}

	private static int getComponentAlignmentLCM(DataOrganization dataOrganization,
			int allComponentsLCM, int packingValue, DataTypeComponent component) {
		int componentAlignment = getPackedAlignment(dataOrganization, packingValue, component);
		allComponentsLCM =
			DataOrganizationImpl.getLeastCommonMultiple(allComponentsLCM, componentAlignment);
		return allComponentsLCM;
	}

	public static int getPackedAlignment(DataOrganization dataOrganization, int packingValue,
			DataTypeComponent component) {

		if (component.isZeroBitFieldComponent() && (component.getParent() instanceof Union) &&
			!dataOrganization.getBitFieldPacking().useMSConvention()) {
			// Zero-length bitfields ignored within unions for non-MSVC cases
			return 0;
		}

		DataType componentDt = component.getDataType();
		int dtSize = componentDt.getLength();
		if (dtSize <= 0) {
			dtSize = component.getLength();
		}
		return getPackedAlignment(dataOrganization, packingValue, componentDt, dtSize);
	}

	private static int getPackedAlignment(int componentAlignment, int forcedAlignment,
			int packingAlignment) {
		// Only do packing if we are not forcing an alignment.
		int alignment = componentAlignment;
		if (packingAlignment != Composite.NOT_PACKING) { // TODO Should this be packingValue > 0?
			if (forcedAlignment > packingAlignment) {
				alignment = forcedAlignment;
			}
			else if (alignment > packingAlignment) {
				alignment = packingAlignment;
			}
		}
		return alignment;
	}

	public static int getPackedAlignment(DataOrganization dataOrganization, int packingAlignment,
			DataType componentDt, int dtSize) {
		int componentAlignment = dataOrganization.getAlignment(componentDt, dtSize);
		int componentForcedAlignment = dataOrganization.getForcedAlignment(componentDt);
		boolean componentForcingAlignment = componentForcedAlignment > 0;
		if (componentForcingAlignment) {
			componentAlignment = DataOrganizationImpl.getLeastCommonMultiple(componentAlignment,
				componentForcedAlignment);
		}
		return getPackedAlignment(componentAlignment, componentForcedAlignment, packingAlignment);
	}

	public static int getAlignment(DataOrganization dataOrganization, Composite dataType) {

		// TODO: goal is to eliminate this method in favor of pack once and remember alignment

		if (!dataType.isInternallyAligned()) {
			return 1; // Unaligned
		}

		int lcm = getCompositeAlignmentMultiple(dataOrganization, dataType);
		int minimumAlignment = dataType.getMinimumAlignment();
		if ((minimumAlignment != Composite.DEFAULT_ALIGNMENT_VALUE) &&
			(lcm % minimumAlignment != 0)) {
			lcm = DataOrganizationImpl.getLeastCommonMultiple(lcm, minimumAlignment);
		}
		int absoluteMaxAlignment = dataOrganization.getAbsoluteMaxAlignment();
		return ((absoluteMaxAlignment == 0) || (lcm < absoluteMaxAlignment)) ? lcm
				: absoluteMaxAlignment;
	}

}
