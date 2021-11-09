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
package ghidra.file.formats.android.oat.oatclass;

import java.io.IOException;

import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * https://android.googlesource.com/platform/art/+/refs/heads/pie-release/runtime/class_status.h#74
 * 
 * https://android.googlesource.com/platform/art/+/refs/heads/android10-release/runtime/class_status.h#74
 *
 */
public enum OatClassStatusEnum_P_10 implements OatClassStatusEnum {

	kNotReady(0),
	kRetired(1),
	kErrorResolved(2),
	kErrorUnresolved(3),
	kIdx(4),
	kLoaded(5),
	kResolving(6),
	kResolved(7),
	kVerifying(8),
	kRetryVerificationAtRuntime(9),
	kVerifyingAtRuntime(10),
	kVerified(11),
	kSuperclassValidated(12),
	kInitializing(13),
	kInitialized(14),
	kLast(14);// kLast = kInitialized

	private byte value;

	private OatClassStatusEnum_P_10(byte value) {
		this.value = value;
	}

	private OatClassStatusEnum_P_10(int value) {
		this.value = (byte) value;
	}

	public byte getValue() {
		return value;
	}

	@Override
	public OatClassStatusEnum get(short value) {
		for (OatClassStatusEnum_P_10 valueX : values()) {
			if (valueX.getValue() == value) {
				return valueX;
			}
		}
		return null;//invalid case
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		EnumDataType enumDataType = new EnumDataType(OatClassStatusEnum_P_10.class.getSimpleName(), 2);
		for (OatClassStatusEnum_P_10 valueX : values()) {
			enumDataType.add(valueX.name(), valueX.getValue());
		}
		enumDataType.setCategoryPath(new CategoryPath("/oat"));
		return enumDataType;
	}
}
