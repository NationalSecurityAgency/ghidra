/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.pe;

/**
 * A class to represent the 
 * <code>IMAGE_ROM_HEADERS</code>
 * struct as defined in 
 * <b><code>winnt.h</code></b>.
 *
 * <pre>
 * typedef struct _IMAGE_ROM_HEADERS {
 *    IMAGE_FILE_HEADER FileHeader;
 *    IMAGE_ROM_OPTIONAL_HEADER OptionalHeader;
 * } IMAGE_ROM_HEADERS, *PIMAGE_ROM_HEADERS;
 * </pre> 
 */
class ROMHeader {
    private FileHeader fileHeader;
    private OptionalHeaderROM optionalHeader;

    public FileHeader getFileHeader() {
		return fileHeader;
	}
    public OptionalHeaderROM getOptionalHeader() {
		return optionalHeader;
	}
}
