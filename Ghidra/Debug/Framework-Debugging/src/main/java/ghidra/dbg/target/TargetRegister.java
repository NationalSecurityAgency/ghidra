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
package ghidra.dbg.target;

import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.util.PathUtils;

/**
 * This is a description of a register
 * 
 * <p>
 * This describes a register abstractly. It does not represent the actual value of a register. For
 * values, see {@link TargetRegisterBank}. The description and values are separated, since the
 * descriptions typically apply to the entire platform, and so can be presented just once.
 */
@DebuggerTargetObjectIface("Register")
public interface TargetRegister extends TargetObject {

	String CONTAINER_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "container";
	String LENGTH_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "length";

	/**
	 * Get the container of this register.
	 * 
	 * <p>
	 * While it is most common for a register descriptor to be an immediate child of its container,
	 * that is not necessarily the case. In fact, some models may present sub-registers as children
	 * of another register. This method is a reliable and type-safe means of obtaining the
	 * container.
	 * 
	 * @return a reference to the container
	 */
	@TargetAttributeType(
		name = CONTAINER_ATTRIBUTE_NAME,
		required = true,
		fixed = true,
		hidden = true)
	default TargetRegisterContainer getContainer() {
		return getTypedAttributeNowByName(CONTAINER_ATTRIBUTE_NAME, TargetRegisterContainer.class,
			null);
	}

	/**
	 * Get the length, in bits, of the register
	 * 
	 * @return the length of the register
	 */
	@TargetAttributeType(
		name = LENGTH_ATTRIBUTE_NAME,
		required = true,
		fixed = true,
		hidden = true)
	default int getBitLength() {
		return getTypedAttributeNowByName(LENGTH_ATTRIBUTE_NAME, Integer.class, 0);
	}

	/**
	 * Get the name of this register
	 * 
	 * <p>
	 * TODO: Instead of overriding getIndex, we should introduce getRegisterName.
	 */
	@Override
	public default String getIndex() {
		return PathUtils.isIndex(getPath()) ? PathUtils.getIndex(getPath())
				: PathUtils.getKey(getPath());
	}

	// TODO: Any typical type assignment or structure definition?
	// TODO: (Related) Should describe if typically a pointer?

	// TODO: What if the register is memory-mapped? Probably map client-side.
}
