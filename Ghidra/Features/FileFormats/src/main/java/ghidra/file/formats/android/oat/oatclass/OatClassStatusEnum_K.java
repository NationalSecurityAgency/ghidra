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
 * <a href="https://android.googlesource.com/platform/art/+/kitkat-release/runtime/mirror/class.h#112">kitkat-release/runtime/mirror/class.h</a>
 * 
 */
public enum OatClassStatusEnum_K implements OatClassStatusEnum {

	kStatusError(-1),
	kStatusNotReady(0),
	kStatusIdx(1),
	kStatusLoaded(2),
	kStatusResolved(3),
	kStatusVerifying(4),
	kStatusRetryVerificationAtRuntime(5),
	kStatusVerifyingAtRuntime(6),
	kStatusVerified(7),
	kStatusInitializing(8),
	kStatusInitialized(9);

	private short value;

	private OatClassStatusEnum_K(short value) {
		this.value = value;
	}

	private OatClassStatusEnum_K(int value) {
		this.value = (short) value;
	}

	public short getValue() {
		return value;
	}

	@Override
	public OatClassStatusEnum get(short value) {
		for (OatClassStatusEnum_K valueX : values()) {
			if (valueX.getValue() == value) {
				return valueX;
			}
		}
		return null;//invalid case
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		EnumDataType enumDataType = new EnumDataType(OatClassStatusEnum_K.class.getSimpleName(), 2);
		for (OatClassStatusEnum_K valueX : values()) {
			enumDataType.add(valueX.name(), valueX.getValue());
		}
		enumDataType.setCategoryPath(new CategoryPath("/oat"));
		return enumDataType;
	}
}
