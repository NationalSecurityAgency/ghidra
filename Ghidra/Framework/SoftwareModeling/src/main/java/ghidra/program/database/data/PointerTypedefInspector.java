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
package ghidra.program.database.data;

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;

/**
 * <code>PointerTypeDefInspector</code> provides utilities for inspecting {@link Pointer} - {@link TypeDef}s.  
 * These special typedefs allow a modified-pointer datatype to be used for special situations where
 * a simple pointer will not suffice and special stored pointer interpretation/handling is required.  
 * <br>
 * The various {@link Pointer} modifiers on the associated {@link TypeDef} are achieved through the use of various
 * {@link TypeDefSettingsDefinition}.  The {@link PointerTypedefBuilder} may be used to simplify the creation
 * of these pointer-typedefs.
 */
public class PointerTypedefInspector {

	private PointerTypedefInspector() {
		// no construct static utility class
	}

	/**
	 * Determine the component-offset for the specified pointerTypeDef based upon
	 * its default settings.
	 * @param pointerTypeDef Pointer TypeDef
	 * @return pointer component offset or 0 if unspecified or not applicable
	 */
	public static long getPointerComponentOffset(TypeDef pointerTypeDef) {
		return pointerTypeDef.isPointer()
				? ComponentOffsetSettingsDefinition.DEF
						.getValue(pointerTypeDef.getDefaultSettings())
				: 0;
	}

	/**
	 * Determine the referenced address space for specified pointerTypeDef based upon
	 * its default settings.
	 * @param pointerTypeDef Pointer TypeDef
	 * @param addrFactory target address factory
	 * @return referenced address space or null if not specified or address space
	 * lookup fails.
	 */
	public static AddressSpace getPointerAddressSpace(TypeDef pointerTypeDef,
			AddressFactory addrFactory) {
		if (!pointerTypeDef.isPointer()) {
			return null;
		}
		Settings settings = pointerTypeDef.getDefaultSettings();
		String spaceName =
			AddressSpaceSettingsDefinition.DEF.getValue(settings);
		if (spaceName == null) {
			return null;
		}
		AddressSpace addressSpace = addrFactory.getAddressSpace(spaceName);
		if (addressSpace instanceof SegmentedAddressSpace) {
			// Other settings do not apply when SegmentedAddressSpace is used
			// see PointerDataType.getAddressValue(MemBuffer, int, Settings)
			return addressSpace;
		}
		// Address space setting ignored if Pointer Type has been specified
		PointerType choice = PointerTypeSettingsDefinition.DEF.getType(settings);
		return choice == PointerType.DEFAULT ? addressSpace : null;
	}

	/**
	 * Determine if the specified pointerTypeDef has a pointer bit-shift specified.
	 * @param pointerTypeDef Pointer TypeDef
	 * @return true if non-zero bit-shift setting exists, else false
	 */
	public static boolean hasPointerBitShift(TypeDef pointerTypeDef) {
		return pointerTypeDef.isPointer()
				? OffsetShiftSettingsDefinition.DEF.hasValue(pointerTypeDef.getDefaultSettings())
				: false;
	}

	/**
	 * Determine the pointer bit-shift for the specified pointerTypeDef based upon
	 * its default settings. A right-shift is specified by a positive value while
	 * a left-shift is specified by a negative value.
	 * If specified, bit-shift will be applied after applying any specified bit-mask.
	 * @param pointerTypeDef Pointer TypeDef
	 * @return pointer bit-shift or 0 if unspecified or not applicable
	 */
	public static long getPointerBitShift(TypeDef pointerTypeDef) {
		return pointerTypeDef.isPointer()
				? OffsetShiftSettingsDefinition.DEF.getValue(pointerTypeDef.getDefaultSettings())
				: 0;
	}

	/**
	 * Determine if the specified pointerTypeDef has a pointer bit-mask specified.
	 * @param pointerTypeDef Pointer TypeDef
	 * @return true if a bit-mask setting exists, else false
	 */
	public static boolean hasPointerBitMask(TypeDef pointerTypeDef) {
		return pointerTypeDef.isPointer()
				? OffsetMaskSettingsDefinition.DEF.hasValue(pointerTypeDef.getDefaultSettings())
				: false;
	}

	/**
	 * Determine the pointer bit-mask for the specified pointerTypeDef based upon
	 * its default settings. If specified, bit-mask will be AND-ed with stored 
	 * offset prior to any specified bit-shift.
	 * @param pointerTypeDef Pointer TypeDef
	 * @return pointer bit-shift or 0 if unspecified or not applicable
	 */
	public static long getPointerBitMask(TypeDef pointerTypeDef) {
		return pointerTypeDef.isPointer()
				? OffsetMaskSettingsDefinition.DEF.getValue(pointerTypeDef.getDefaultSettings())
				: 0;
	}

	/**
	 * Get the pointer type (see {@link PointerType}).
	 * @param pointerTypeDef Pointer TypeDef
	 * @return pointer type or null if not a pointer
	 */
	public static PointerType getPointerType(TypeDef pointerTypeDef) {
		return pointerTypeDef.isPointer()
				? PointerTypeSettingsDefinition.DEF.getType(pointerTypeDef.getDefaultSettings())
				: null;
	}

}
