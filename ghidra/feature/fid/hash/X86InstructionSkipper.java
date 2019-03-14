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
package ghidra.feature.fid.hash;

import ghidra.program.model.lang.Processor;
import ghidra.util.search.InstructionSkipper;

/**
 * These are the NOP instructions laid down by Visual Studio (or potentially
 * other compilers, like gcc) as advised by Intel.  They represent "do nothing"
 * operations of various sizes which are used for dynamic code patching.
 */
public class X86InstructionSkipper implements InstructionSkipper {

	// IF YOU CHANGE THIS, YOU MUST INCREMENT LibrariesTable.VERSION
	// AND REBUILD ALL THE VISUAL STUDIO LIBRARIES (or anything else
	// that uses the x86 32-bit processor)

	// @formatter:off
	private static final byte[][] PATTERNS = {
		{ (byte) 0x90 },
		{ (byte) 0x8b, (byte) 0xc0 },
		{ (byte) 0x8b, (byte) 0xc9 },
		{ (byte) 0x8b, (byte) 0xd2 },
		{ (byte) 0x8b, (byte) 0xdb },
		{ (byte) 0x8b, (byte) 0xe4 },
		{ (byte) 0x8b, (byte) 0xed },
		{ (byte) 0x8b, (byte) 0xf6 },
		{ (byte) 0x8b, (byte) 0xff },
		{ 0x66, (byte) 0x90 },
		{ 0x0f, 0x1f, 0x00 },
		{ 0x0f, 0x1f, 0x40, 0x00 },
		{ 0x0f, 0x1f, 0x44, 0x00, 0x00 },
		{ 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00 },
		{ 0x0f, 0x1f, (byte) 0x80, 0x00, 0x00, 0x00, 0x00 },
		{ 0x0f, 0x1f, (byte) 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 },
		{ 0x66, 0x0f, 0x1f, (byte) 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 },
	};
	// @formatter:on

	@Override
	public Processor getApplicableProcessor() {
		return Processor.findOrPossiblyCreateProcessor("x86");
	}

	@Override
	public boolean shouldSkip(byte[] buffer,int size) {
		for (int ii = 0; ii < PATTERNS.length; ++ii) {
			byte[] pat = PATTERNS[ii];
			if (pat.length != size) continue;
			int i;
			for(i=0;i<size;++i) {
				if (pat[i] != buffer[i]) break;
			}
			if (i==size) return true;
		}
		return false;
	}
}
