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
package ghidra.app.util.bin.format.elf.relocation;

public class I960_ElfRelocationConstants {
	public static final int R_960_NONE = 0;
	public static final int R_960_12 = 1;
	public static final int R_960_32 = 2;
	public static final int R_960_IP24 = 3;
	public static final int R_960_SUB = 4;
	public static final int R_960_OPTCALL = 5;
	public static final int R_960_OPTCALLX = 6;
	public static final int R_960_OPTCALLXA = 7;
}
