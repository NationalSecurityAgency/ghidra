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
package ghidra.app.util.bin.format.pe.cli.blobs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.program.model.data.*;
import ghidra.util.Msg;

public class CliSigAssembly extends CliAbstractSig {
	byte[] sha1Hash = new byte[CLISIGASSEMBLY_SHA1_LENGTH];
	int bitLength;
	int publicExponent;
	byte[] publicKeySignature;

	// "RSA1" magic value from _RSAPUBKEY structure
	private static final int CLISIGASSEMBLY_RSA1_MAGIC = 0x31415352;
	private static final int CLISIGASSEMBLY_SHA1_LENGTH = 20;
	private static final int BITS_PER_BYTE = 8;

	public CliSigAssembly(CliBlob blob) throws IOException {
		super(blob);

		BinaryReader reader = blob.getContentsReader();
		sha1Hash = reader.readNextByteArray(CLISIGASSEMBLY_SHA1_LENGTH);

		if (reader.readNextUnsignedInt() != CLISIGASSEMBLY_RSA1_MAGIC) {
			Msg.warn(this, "An Assembly blob was found without the expected RSA1 signature: " +
				this.getName());
			return;
		}

		bitLength = reader.readNextInt();
		publicExponent = reader.readNextInt();
		publicKeySignature = reader.readNextByteArray(bitLength / BITS_PER_BYTE);
	}

	@Override
	public DataType getContentsDataType() {
		StructureDataType struct = new StructureDataType(new CategoryPath(PATH), getName(), 0);
		struct.add(new ArrayDataType(BYTE, sha1Hash.length, 1), "sha1", "SHA1 hash");
		struct.add(DWORD, "_RSAPUBKEY.magic", "RSA1 Magic");
		struct.add(DWORD, "_RSAPUBKEY.bitlen", "");
		struct.add(DWORD, "_RSAPUBKEY.pubexp", "");
		struct.add(new ArrayDataType(BYTE, publicKeySignature.length, 1), "pubkey", "Public Key");
		return struct;
	}

	@Override
	public String getContentsName() {
		return "AssemblySig";
	}

	@Override
	public String getContentsComment() {
		return "Data describing an Assembly signature";
	}

	@Override
	public String getRepresentationCommon(CliStreamMetadata stream, boolean isShort) {
		return String.format(
			"Assembly:\r\tSHA1: %s\r\tBit length: %d\r\tPublic exponent: %d\r\tSignature: %s",
			sha1Hash.toString(), bitLength, publicExponent, publicKeySignature);
	}

}
