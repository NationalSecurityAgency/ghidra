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
package ghidra.file.formats.ios.dmg;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

class DmgHeaderV2_old extends DmgHeader {
	public final byte [] sig;
	public final int     version;
	public final int     enc_iv_size;
	public final int     unk1;
	public final int     unk2;
	public final int     unk3;
	public final int     unk4;
	public final int     unk5;
	public final byte [] uuid;
	public final int     blocksize;
	public final long    datasize;
	public final long    dataoffset;
	public final byte [] filler1;
	public final int     kdf_algorithm;
	public final int     kdf_prng_algorithm;
	public final int     kdf_iteration_count;
	public final int     kdf_salt_len;
	public final byte [] kdf_salt;
	public final int     blob_enc_iv_size;
	public final byte [] blob_enc_iv;
	public final int     blob_enc_key_bits;
	public final int     blob_enc_algorithm;
	public final int     blob_enc_padding;
	public final int     blob_enc_mode;
	public final int     encrypted_keyblob_size;
	public final byte [] encrypted_keyblob;

	public DmgHeaderV2_old(BinaryReader reader) throws IOException {
		sig                      = reader.readNextByteArray( 8 );
		version                  = reader.readNextInt();
		enc_iv_size              = reader.readNextInt();
		unk1                     = reader.readNextInt();
		unk2                     = reader.readNextInt();
		unk3                     = reader.readNextInt();
		unk4                     = reader.readNextInt();
		unk5                     = reader.readNextInt();
		uuid                     = reader.readNextByteArray( 16 );
		blocksize                = reader.readNextInt();
		datasize                 = reader.readNextLong();
		dataoffset               = reader.readNextLong();
		filler1                  = reader.readNextByteArray( 0x260 );
		kdf_algorithm            = reader.readNextInt();
		kdf_prng_algorithm       = reader.readNextInt();
		kdf_iteration_count      = reader.readNextInt();
		kdf_salt_len             = reader.readNextInt();
		kdf_salt                 = reader.readNextByteArray( 32 );
		blob_enc_iv_size         = reader.readNextInt();
		blob_enc_iv              = reader.readNextByteArray( 32 );
		blob_enc_key_bits        = reader.readNextInt();
		blob_enc_algorithm       = reader.readNextInt();
		blob_enc_padding         = reader.readNextInt();
		blob_enc_mode            = reader.readNextInt();
		encrypted_keyblob_size   = reader.readNextInt();
		encrypted_keyblob        = reader.readNextByteArray( 0x30 );
	}

	@Override
	public byte [] getSignature() {
		return sig;
	}

	@Override
	public int getVersion() {
		return version;
	}

	@Override
	public long getDataSize() {
		return datasize;
	}
	@Override
	public long getDataOffset() {
		return dataoffset;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType( this );
	}

}
