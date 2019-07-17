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
import ghidra.util.exception.NotYetImplementedException;

class DmgHeaderV1_old extends DmgHeader {
	public final byte [] filler1;
	public final int     kdf_iteration_count;
	public final int     kdf_salt_len;
	public final byte [] kdf_salt;
	public final byte [] unwrap_iv;
	public final int     len_wrapped_aes_key;
	public final byte [] wrapped_aes_key;
	public final int     len_hmac_sha1_key;
	public final byte [] wrapped_hmac_sha1_key;
	public final int     len_integrity_key;
	public final byte [] wrapped_integrity_key;
	public final byte [] filler6;

	public DmgHeaderV1_old(BinaryReader reader) throws IOException {
		filler1                =  reader.readNextByteArray( 48 );
		kdf_iteration_count    =  reader.readNextInt();
		kdf_salt_len           =  reader.readNextInt();
		kdf_salt               =  reader.readNextByteArray( 48 );
		unwrap_iv              =  reader.readNextByteArray( 32 );
		len_wrapped_aes_key    =  reader.readNextInt();
		wrapped_aes_key        =  reader.readNextByteArray( 296 );
		len_hmac_sha1_key      =  reader.readNextInt();
		wrapped_hmac_sha1_key  =  reader.readNextByteArray( 300 );
		len_integrity_key      =  reader.readNextInt();
		wrapped_integrity_key  =  reader.readNextByteArray( 48 );
		filler6                =  reader.readNextByteArray( 484 );
	}

	@Override
	public byte[] getSignature() {
		throw new NotYetImplementedException();
	}

	@Override
	public long getDataOffset() {
		throw new NotYetImplementedException();
	}

	@Override
	public long getDataSize() {
		throw new NotYetImplementedException();
	}

	@Override
	public int getVersion() {
		throw new NotYetImplementedException();
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType( DmgHeaderV1_old.class );
	}
}
