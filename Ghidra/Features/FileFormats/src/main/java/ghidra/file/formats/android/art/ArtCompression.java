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
package ghidra.file.formats.android.art;

public interface ArtCompression {

	/**
	 * Storage method for the image, the image may be compressed.
	 * @return the storage method
	 * @throws UnknownArtStorageModeException when an unknown storage mode is encountered
	 */
	public ArtStorageMode getStorageMode() throws UnknownArtStorageModeException;

	/**
	 * Data size for the image data excluding the bitmap and the header. 
	 * For compressed images, this is the compressed size in the file.
	 * @return the compressed size
	 */
	public int getCompressedSize();

	/**
	 * Offset to the start of the compressed bytes.
	 * Also, offset of where to place the decompressed bytes.
	 * @return the offset to the compressed bytes
	 */
	public long getCompressedOffset();

	/**
	 * Expected size of the decompressed bytes.
	 * @return the expected decompressed size
	 */
	public int getDecompressedSize();

	/**
	 * Offset to the start of the decompressed bytes.
	 * @return the offset to the dcompressed bytes
	 */
	public long getDecompressedOffset();
}
