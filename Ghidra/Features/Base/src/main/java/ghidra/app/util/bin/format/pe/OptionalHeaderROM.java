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
 * A class to represent the IMAGE_ROM_OPTIONAL_HEADER 
 * data structure.
 * <br>
 * <pre>
 * typedef struct _IMAGE_ROM_OPTIONAL_HEADER {
 *     WORD   Magic;
 *     BYTE   MajorLinkerVersion;
 *     BYTE   MinorLinkerVersion;
 *     DWORD  SizeOfCode;
 *     DWORD  SizeOfInitializedData;
 *     DWORD  SizeOfUninitializedData;
 *     DWORD  AddressOfEntryPoint;
 *     DWORD  BaseOfCode;
 *     DWORD  BaseOfData;
 *     DWORD  BaseOfBss;
 *     DWORD  GprMask;
 *     DWORD  CprMask[4];
 *     DWORD  GpValue;
 * } IMAGE_ROM_OPTIONAL_HEADER, *PIMAGE_ROM_OPTIONAL_HEADER;
 * </pre>
 */
public class OptionalHeaderROM {
    private short    magic;
    private byte     majorLinkerVersion;
    private byte     minorLinkerVersion;
    private int      sizeOfCode;
    private int      sizeOfInitializedData;
    private int      sizeOfUninitializedData;
    private int      addressOfEntryPoint;
    private int      baseOfCode;
    private int      baseOfData;
    private int      baseOfBss;
    private int      gprMask;
    private int []   cprMask;
    private int      gpValue;

    public short getMagic() {
		return magic;
	}
    public byte getMajorLinkerVersion() {
		return majorLinkerVersion;
	}
    public byte getMinorLinkerVersion() {
		return minorLinkerVersion;
	}
    public int getSizeOfCode() {
		return sizeOfCode;
	}
    public int getSizeOfInitializedData() {
		return sizeOfInitializedData;
	}
    public int getSizeOfUninitializedData() {
		return sizeOfUninitializedData;
	}
    public int getAddressOfEntryPoint() {
		return addressOfEntryPoint;
	}
    public int getBaseOfCode() {
		return baseOfCode;
	}
    public int getBaseOfData() {
		return baseOfData;
	}
    public int getBaseOfBss() {
		return baseOfBss;
	}
    public int getGprMask() {
		return gprMask;
	}
    public int[] getCprMask() {
		return cprMask;
	}
    public int getGpValue() {
		return gpValue;
	}
}
