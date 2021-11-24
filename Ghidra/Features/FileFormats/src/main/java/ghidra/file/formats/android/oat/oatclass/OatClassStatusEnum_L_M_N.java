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
 * https://android.googlesource.com/platform/art/+/lollipop-release/runtime/mirror/class.h#133
 * 
 * https://android.googlesource.com/platform/art/+/refs/heads/lollipop-mr1-fi-release/runtime/mirror/class.h#138
 * 
 * https://android.googlesource.com/platform/art/+/refs/heads/lollipop-wear-release/runtime/mirror/class.h#119
 * 
 * https://android.googlesource.com/platform/art/+/marshmallow-release/runtime/mirror/class.h#112
 * 
 * https://android.googlesource.com/platform/art/+/nougat-release/runtime/mirror/class.h#116
 */
public enum OatClassStatusEnum_L_M_N implements OatClassStatusEnum {

	kStatusRetired(-2),
	kStatusError(-1),
	kStatusNotReady(0),
	kStatusIdx(1),
	kStatusLoaded(2),
	kStatusResolving(3),
	kStatusResolved(4),
	kStatusVerifying(5),
	kStatusRetryVerificationAtRuntime(6),
	kStatusVerifyingAtRuntime(7),
	kStatusVerified(8),
	kStatusInitializing(9),
	kStatusInitialized(10),
	kStatusMax(11);

	private short value;

	private OatClassStatusEnum_L_M_N(short value) {
		this.value = value;
	}

	private OatClassStatusEnum_L_M_N(int value) {
		this.value = (short) value;
	}

	public short getValue() {
		return value;
	}

	@Override
	public OatClassStatusEnum get(short value) {
		for (OatClassStatusEnum_L_M_N valueX : values()) {
			if (valueX.getValue() == value) {
				return valueX;
			}
		}
		return null;//invalid case
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		EnumDataType enumDataType = new EnumDataType(OatClassStatusEnum_L_M_N.class.getSimpleName(), 2);
		for (OatClassStatusEnum_L_M_N valueX : values()) {
			enumDataType.add(valueX.name(), valueX.getValue());
		}
		enumDataType.setCategoryPath(new CategoryPath("/oat"));
		return enumDataType;
	}
}
