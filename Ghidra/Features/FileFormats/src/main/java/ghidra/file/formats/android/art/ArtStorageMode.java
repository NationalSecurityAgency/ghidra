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

/**
 * https://android.googlesource.com/platform/art/+/refs/heads/pie-release/runtime/image.h
 */
public enum ArtStorageMode {
	kStorageModeUncompressed, kStorageModeLZ4, kStorageModeLZ4HC, kStorageModeCount;  // Number of elements in enum.

	public final static ArtStorageMode kDefaultStorageMode = kStorageModeUncompressed;

	public final static int SIZE = 32;//bits

	public static ArtStorageMode get(int value) throws UnknownArtStorageModeException {
		for (ArtStorageMode mode : values()) {
			if (mode.ordinal() == value) {
				return mode;
			}
		}
		throw new UnknownArtStorageModeException(value);
	}
}
