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
package ghidra.file.formats.iso9660;

/*
 * Documentation gathered from http://wiki.osdev.org/ISO_9660
 */
public final class ISO9660Constants {

	/*
	 * Volume Descriptor Type Codes
	 */
	public final static byte VOLUME_DESC_BOOT_RECORD = 0x0;
	public final static byte VOLUME_DESC_PRIMARY_VOLUME_DESC = 0x1;
	public final static byte VOLUME_DESC_SUPPL_VOLUME_DESC = 0x2;
	public final static byte VOLUME_PARTITION_DESC = 0x3;
	public final static byte VOLUME_DESC_SET_TERMINATOR = (byte) 0xff;

	/*
	 * Magic number identifier
	 */
	public final static String MAGIC_STRING = "CD001";
	public final static byte[] MAGIC_BYTES = { 0x43, 0x44, 0x30, 0x30, 0x31 };

	public final static int HIDDEN_FILE_FLAG = 0;
	public final static int DIRECTORY_FLAG = 1;
	public final static int ASSOCIATED_FILE_FLAG = 2;
	public final static int EXTENDED_ATTRIBUTE_RECORD_INFO_FLAG = 3;
	public final static int OWNER_GROUP_PERMISSIONS_FLAG = 4;
	public final static int NOT_FINAL_DIRECTORY_RECORD_FLAG = 5;

	public final static Short SECTOR_LENGTH = 0x800;

	public final static Byte FILE_STRUCTURE_VERISON = 0x01;

	public final static Short APPLICATION_USED_LENGTH = 0x200;

	/*
	 * Lists the three possible address offsets where the ISO9660
	 * file signature can be located
	 */
	public final static int SIGNATURE_OFFSET1_0x8001 = 0x8001;
	public final static int SIGNATURE_OFFSET2_0x8801 = 0x8801;
	public final static int SIGNATURE_OFFSET3_0x9001 = 0x9001;

	public final static int MIN_ISO_LENGTH1 = 0x8800;
	public final static int MIN_ISO_LENGTH2 = 0x9000;
	public final static int MIN_ISO_LENGTH3 = 0x9800;

	public final static byte BAD_TYPE = -2;

	public final static int UNUSED_SPACER_LEN_32 = 32;
	public final static int UNUSED_SPACER_LEN_512 = 512;
	public final static int RESERVED_SIZE = 653;
	public final static int IDENTIFIER_LENGTH_32 = 32;
	public final static int IDENTIFIER_LENGTH_36 = 36;
	public final static int IDENTIFIER_LENGTH_37 = 37;
	public final static int IDENTIFIER_LENGTH_38 = 38;
	public final static int IDENTIFIER_LENGTH_128 = 128;
	public final static int BOOT_SYSTEM_USE_LENGTH = 1977;
	public final static int DATE_TIME_LENGTH_7 = 7;
	public final static int DATE_TIME_LENGTH_17 = 17;

}
