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
			CompositeInternal composite) {
		int allComponentsLCM = 1;
		int packingValue = composite.getStoredPackingValue();

		DataTypeComponent[] dataTypeComponents = composite.getDefinedComponents();
		for (DataTypeComponent dataTypeComponent : dataTypeComponents) {
			int impartedAlignment = CompositeAlignmentHelper.getPackedAlignment(dataOrganization,
				packingValue, dataTypeComponent);
			if (impartedAlignment != 0) {
				allComponentsLCM = DataOrganizationImpl.getLeastCommonMultiple(allComponentsLCM,
					impartedAlignment);
			}
		}
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
		return getPackedAlignment(componentDt.getAlignment(), packingValue);
	}

	static int getPackedAlignment(int componentAlignment, int packingValue) {
		int alignment = componentAlignment;
		if (packingValue > 0 && packingValue < componentAlignment) {
			alignment = packingValue;
		}
		return alignment;
	}

	public static int getAlignment(DataOrganization dataOrganization, CompositeInternal composite) {

		// TODO: goal is to eliminate this method in favor of pack once and remember alignment

		int minimumAlignment = composite.getStoredMinimumAlignment();
		if (minimumAlignment < CompositeInternal.DEFAULT_ALIGNMENT) {
			minimumAlignment = dataOrganization.getMachineAlignment();
		}
		
		if (!composite.isPackingEnabled()) {
			return minimumAlignment == CompositeInternal.DEFAULT_ALIGNMENT ? 1 : minimumAlignment;
		}

		int lcm = getCompositeAlignmentMultiple(dataOrganization, composite);
		if ((minimumAlignment != CompositeInternal.DEFAULT_ALIGNMENT) &&
			(lcm % minimumAlignment != 0)) {
			lcm = DataOrganizationImpl.getLeastCommonMultiple(lcm, minimumAlignment);
		}
		int absoluteMaxAlignment = dataOrganization.getAbsoluteMaxAlignment();
		return ((absoluteMaxAlignment == 0) || (lcm < absoluteMaxAlignment)) ? lcm
				: absoluteMaxAlignment;
	}

}
