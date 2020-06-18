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
package ghidra.file.formats.android.oat;

/**
 * https://android.googlesource.com/platform/art/+/refs/heads/lollipop-release/runtime/instruction_set.h#29
 */
public enum OatInstructionSet {
	kNone, kArm, kArm64, kThumb2, kX86, kX86_64, kMips, kMips64;

	public final static String DISPLAY_NAME = "instruction_set_";

	public static OatInstructionSet valueOf(int instructionSet) {
		try {
			return OatInstructionSet.values()[instructionSet];
		}
		catch (Exception e) {
			return null;
		}
	}

}
