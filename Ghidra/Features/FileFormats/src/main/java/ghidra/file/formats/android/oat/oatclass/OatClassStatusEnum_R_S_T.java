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
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/android11-release/runtime/class_status.h#82">android11-release/runtime/class_status.h</a>
 * <br>
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/android12-release/runtime/class_status.h#82">android12-release/runtime/class_status.h</a>
 * <br>
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/android13-release/runtime/class_status.h#82">android13-release/runtime/class_status.h</a>
 */
public enum OatClassStatusEnum_R_S_T implements OatClassStatusEnum {

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
	kVerifiedNeedsAccessChecks(10),
	kVerified(11),
	kSuperclassValidated(12),
	kInitializing(13),
	kInitialized(14),
	kVisiblyInitialized(15),
	kLast(15);// kLast = kVisiblyInitialized

	private byte value;

	private OatClassStatusEnum_R_S_T(byte value) {
		this.value = value;
	}

	private OatClassStatusEnum_R_S_T(int value) {
		this.value = (byte) value;
	}

	public byte getValue() {
		return value;
	}

	@Override
	public OatClassStatusEnum get(short value) {
		for (OatClassStatusEnum_R_S_T valueX : values()) {
			if (valueX.getValue() == value) {
				return valueX;
			}
		}
		return null;//invalid case
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		EnumDataType enumDataType = new EnumDataType(OatClassStatusEnum_R_S_T.class.getSimpleName(), 2);
		for (OatClassStatusEnum_R_S_T valueX : values()) {
			enumDataType.add(valueX.name(), valueX.getValue());
		}
		enumDataType.setCategoryPath(new CategoryPath("/oat"));
		return enumDataType;
	}
}
