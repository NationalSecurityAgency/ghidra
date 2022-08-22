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
package ghidra.file.formats.android.fbpk;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;

public final class FBPK_Constants {

	public static final int VERSION_1 = 1;
	public static final int VERSION_2 = 2;

	public static final String FBPK = "FBPK";
	public static final String FBPT = "FBPT";
	public static final String UFPK = "UFPK";
	public static final String UFSM = "UFSM";
	public static final String UFSP = "UFSP";

	public static final int FBPK_MAGIC = 0x4B504246;
	public static final int FBPT_MAGIC = 0x54504246;
	public static final int UFPK_MAGIC = 0x4B504655;
	public static final int UFSM_MAGIC = 0x4D534655;
	public static final int UFSP_MAGIC = 0x50534655;

	public static final int NAME_MAX_LENGTH = 36;
	public static final int PARTITION_TYPE_DIRECTORY = 0;
	public static final int PARTITION_TYPE_FILE = 1;

	public static final String PARTITION_TABLE = "partition table";
	public static final String V1_LAST_PARTITION_ENTRY = "last_parti";


	public static final int V1_VERSION_MAX_LENGTH = 68;
	public static final int V1_PADDING_LENGTH = 2;

	public static final String V2_PARTITION = "partition:";
	public static final String V2_UFS = "ufs";
	public static final Object V2_UFSFWUPDATE = "ufsfwupdate";

	public static final int V2_PARTITION_NAME_MAX_LENGTH = 76;
	public static final int V2_STRING1_MAX_LENGTH = 16;
	public static final int V2_STRING2_MAX_LENGTH = 68;
	public static final int V2_FORMAT_MAX_LENGTH = 14;
	public static final int V2_GUID_MAX_LENGTH = 44;
	public static final int V2_UFPK_STRING1_MAX_LENGTH = 76;
	
	public static boolean isFBPK(Program program) {
		try {
			Memory memory = program.getMemory();
			int magic = memory.getInt(program.getMinAddress());
			return magic == FBPK_MAGIC;
		}
		catch (Exception e) {
			//ignore
		}
		return false;
	}

}
