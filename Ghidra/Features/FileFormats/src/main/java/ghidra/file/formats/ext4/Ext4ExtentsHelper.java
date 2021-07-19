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
package ghidra.file.formats.ext4;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.formats.gfilesystem.FSRL;

/**
 * Helper class that handles the extent data stored in an inode's i_block[] array
 */
public class Ext4ExtentsHelper {

	/**
	 * Creates a {@link RangeMappedByteProvider} from the extents data found in the
	 * inode's i_block field.
	 *   
	 * @param rawIBlockBytes raw bytes from the inode's i_block
	 * @param provider the file system volume provider
	 * @param expectedLength the length the file should be (from the inode)
	 * @param blockSize file system blockSize 
	 * @param fsrl {@link FSRL} to assign to the new ByteProvider
	 * @return new {@link ByteProvider} containing the blocks of the volume that were specified
	 * by the extent data
	 * @throws IOException if error
	 */
	public static ByteProvider getByteProvider(byte[] rawIBlockBytes, ByteProvider provider,
			long expectedLength, int blockSize, FSRL fsrl) throws IOException {
		BinaryReader iBlockReader =
			new BinaryReader(new ByteArrayProvider(rawIBlockBytes), true /* LE */);

		RangeMappedByteProvider ebp = new RangeMappedByteProvider(provider, fsrl);
		processExtents(iBlockReader, provider, ebp, blockSize, expectedLength);
		if (ebp.length() < expectedLength) {
			// trailing sparse.  not sure if possible.
			ebp.addSparseRange(expectedLength - ebp.length());
		}

		return ebp;
	}

	private static void processExtents(BinaryReader reader, ByteProvider provider,
			RangeMappedByteProvider ebp, int blockSize, long expectedLength) throws IOException {
		Ext4ExtentHeader header = Ext4ExtentHeader.read(reader);
		if ( header == null ) {
			throw new IOException("Bad/missing extents header");
		}
		if (header.getEh_depth() == 0) {
			for (int i = 0; i < header.getEh_entries() && ebp.length() < expectedLength; i++) {
				Ext4Extent extent = new Ext4Extent(reader);
				
				long startPos = extent.getStreamBlockNumber() * blockSize;
				long providerOfs = extent.getExtentStartBlockNumber() * blockSize;
				long extentLen = extent.getExtentBlockCount() * blockSize;
				if (ebp.length() < startPos) {
					ebp.addSparseRange(startPos - ebp.length());
				}
				if (ebp.length() + extentLen > expectedLength) {
					// the last extent may have a trailing partial block
					extentLen = expectedLength - ebp.length();
				}

				ebp.addRange(providerOfs, extentLen);
			}
		}
		else {
			for (int i = 0; i < header.getEh_entries(); i++) {
				Ext4ExtentIdx idx = new Ext4ExtentIdx(reader);
				long offset = idx.getEi_leaf() * blockSize;
				try (ByteProviderWrapper bpw =
					new ByteProviderWrapper(provider, offset, blockSize)) {
					BinaryReader subReader = new BinaryReader(bpw, true /* LE */);
					processExtents(subReader, provider, ebp, blockSize, expectedLength);
				}
			}
		}

	}


}
