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
package ghidra.dbg.sctl.protocol.consts;

import ghidra.dbg.attributes.TargetPrimitiveDataType.PrimitiveKind;

/**
 * See the SCTL documentation
 */
public enum Rkind {
	Rundef(1, PrimitiveKind.UNDEFINED),
	// Unsigned little-endian
	Ru08le(1, PrimitiveKind.UINT),
	Ru16le(2, PrimitiveKind.UINT),
	Ru32le(4, PrimitiveKind.UINT),
	Ru64le(8, PrimitiveKind.UINT),
	// Signed little-endian
	Rs08le(1, PrimitiveKind.SINT),
	Rs16le(2, PrimitiveKind.SINT),
	Rs32le(4, PrimitiveKind.SINT),
	Rs64le(8, PrimitiveKind.SINT),
	// Unsigned big-endian
	Ru08be(1, PrimitiveKind.UINT),
	Ru16be(2, PrimitiveKind.UINT),
	Ru32be(4, PrimitiveKind.UINT),
	Ru64be(8, PrimitiveKind.UINT),
	// Signed big-endian
	Rs08be(1, PrimitiveKind.SINT),
	Rs16be(2, PrimitiveKind.SINT),
	Rs32be(4, PrimitiveKind.SINT),
	Rs64be(8, PrimitiveKind.SINT),
	// Floating-point
	Rf32(4, PrimitiveKind.FLOAT),
	Rf64(8, PrimitiveKind.FLOAT),
	Rf96(12, PrimitiveKind.FLOAT),
	Rf128(16, PrimitiveKind.FLOAT),
	// Complex floating-point
	Rx64(8, PrimitiveKind.COMPLEX),
	Rx128(16, PrimitiveKind.COMPLEX),
	Rx192(24, PrimitiveKind.COMPLEX);

	private final int byteLength;
	private final PrimitiveKind kind;

	Rkind(int byteLength, PrimitiveKind kind) {
		this.byteLength = byteLength;
		this.kind = kind;
	}

	public int getByteLength() {
		return byteLength;
	}

	public PrimitiveKind getKind() {
		return kind;
	}
}
