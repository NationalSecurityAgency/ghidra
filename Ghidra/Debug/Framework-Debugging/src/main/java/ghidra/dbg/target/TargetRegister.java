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
 * There are two conventions for presenting registers and their values:
 * 
 * <ol>
 * <li><b>Descriptions separated from values:</b> In this convention, the target presents one
 * {@link TargetRegisterContainer}, and in it the various {@link TargetRegister}s, perhaps organized
 * into groups. Each {@link TargetRegister} is then just an abstract description of the register,
 * notably its name and size. Values are read and written using the
 * {@link TargetRegisterBank#readRegister(TargetRegister)} and
 * {@link TargetRegisterBank#writeRegister(TargetRegister, byte[])} methods, and related convenience
 * methods. The {@link TargetRegisterBank} is the suitable bank for the desired object, usually a
 * thread or frame.</li>
 * <li><b>Descriptions and values together:</b> In this convention, the
 * {@link TargetRegisterContainer} is the same object as the {@link TargetRegisterBank}, and so its'
 * replicated for every object that has registers. The registers may be presented in groups under
 * the container/bank. Each register provides its name (i.e., its index or key), its size, and its
 * value (in the {@value TargetObject#VALUE_ATTRIBUTE_NAME} attribute).</li>
 * </ol>
 * 
 * <p>
 * Despite the apparent efficiencies of presenting the descriptions only once, we are gravitating
 * toward the descriptions-and-values together convention. This simplifies the client and
 * model-inspection code a bit and will make things easier if we ever deal with targets having mixed
 * architectures. If we settle on this convention, we will probably remove the
 * {@link TargetRegisterContainer} interface in favor of using {@link TargetRegisterBank}. We may
 * also formally introduce a {@code TargetRegisterGroup} interface.
 */
@DebuggerTargetObjectIface("Register")
public interface TargetRegister extends TargetObject {

	String CONTAINER_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "container";
	String BIT_LENGTH_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "length";

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
		name = BIT_LENGTH_ATTRIBUTE_NAME,
		required = true,
		fixed = true,
		hidden = true)
	default int getBitLength() {
		return getTypedAttributeNowByName(BIT_LENGTH_ATTRIBUTE_NAME, Integer.class, 0);
	}

	/**
	 * Get the length, in bytes, of the register
	 * 
	 * <p>
	 * For registers whose bit lengths are not a multiple of 8, this should be the minimum number of
	 * bytes required to bit all the bits, i.e., it should divide by 8 rounding up.
	 * 
	 * @return the length of the register
	 */
	default int getByteLength() {
		return (getBitLength() + 7) / 8;
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
