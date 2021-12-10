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
package ghidra.file.formats.android.bootimg;

import ghidra.app.util.bin.StructConverter;
import ghidra.util.NumericUtilities;

public abstract class BootImageHeader implements StructConverter {
	/**
	 * Returns the Boot Image MAGIC value.
	 * @see BootImageConstants
	 * @return the Boot Image MAGIC value
	 */
	public abstract String getMagic();

	/**
	 * Returns the page size, as defined in the header.
	 * @return the page size, as defined in the header
	 */
	public abstract int getPageSize();

	/**
	 * Aligns a value upwards to nearest page boundary.
	 *  
	 * @param value unsigned value to align
	 * @return value rounded up to next page size (if not already aligned)
	 */
	public long pageAlign(long value) {
		return NumericUtilities.getUnsignedAlignedValue(value, getPageSize());
	}

	/**
	 * Returns the kernel size, as defined in the header.
	 * @return the kernel size, as defined in the header
	 */
	public abstract int getKernelSize();

	/**
	 * Returns the number of pages used to store the kernel.
	 * @return the number of pages used to store the kernel
	 */
	public abstract int getKernelPageCount();

	/**
	 * Returns the kernel file offset
	 * @return the kernel file offset
	 */
	public abstract long getKernelOffset();

	/**
	 * Returns the ramdisk size, as defined in the header.
	 * @return the ramdisk size, as defined in the header
	 */
	public abstract int getRamdiskSize();

	/**
	 * Returns the number of pages used to store the ramdisk.
	 * @return the number of pages used to store the ramdisk
	 */
	public abstract int getRamdiskPageCount();

	/**
	 * Returns the ramdisk file offset.
	 * @return the ramdisk file offset
	 */
	public abstract int getRamdiskOffset();

	/**
	 * Returns the second stage size, as defined in the header.
	 * @return the second stage size, as defined in the header
	 */
	public abstract int getSecondSize();

	/**
	 * Returns the number of pages used to store the second stage.
	 * @return the number of pages used to store the second stage
	 */
	public abstract int getSecondPageCount();

	/**
	 * Returns the second stage file offset.
	 * @return the second stage file offset
	 */
	public abstract long getSecondOffset();

	/**
	 * Returns the kernel commandline.
	 * @return the kernel commandline
	 */
	public abstract String getCommandLine();
}
