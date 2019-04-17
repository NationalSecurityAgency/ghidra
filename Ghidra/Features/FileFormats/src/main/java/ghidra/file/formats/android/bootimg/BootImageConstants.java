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

public final class BootImageConstants {

	public final static String  BOOT_IMAGE_MAGIC       = "ANDROID!";

	public final static byte [] BOOT_IMAGE_MAGIC_BYTES = BOOT_IMAGE_MAGIC.getBytes();

	public final static int     BOOT_IMAGE_MAGIC_SIZE  = BOOT_IMAGE_MAGIC.length();

	public final static int     BOOT_NAME_SIZE         = 16;
 
	public final static int     BOOT_ARGS_SIZE         = 512;

	public final static String  SECOND_STAGE           = "second stage";

	public final static String  RAMDISK                = "ramdisk";

	public final static String  KERNEL                 = "kernel";

}
