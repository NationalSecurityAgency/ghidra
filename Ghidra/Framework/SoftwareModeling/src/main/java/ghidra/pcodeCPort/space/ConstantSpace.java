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
package ghidra.pcodeCPort.space;

import java.io.PrintStream;

import ghidra.pcodeCPort.error.LowlevelError;
import ghidra.pcodeCPort.translate.Translate;
import ghidra.program.model.lang.SpaceNames;
import ghidra.program.model.pcode.Encoder;

public class ConstantSpace extends AddrSpace {
	public ConstantSpace(Translate t) {
		super(t, spacetype.IPTR_CONSTANT, SpaceNames.CONSTANT_SPACE_NAME, 8, 1,
			SpaceNames.CONSTANT_SPACE_INDEX, 0, 0);
		clearFlags(heritaged | big_endian);
		setFlags(big_endian);
	}

	@Override
	public int printRaw(PrintStream s, long offset) {
		s.append("0x");
		s.append(Long.toHexString(offset));
		return getTrans().getDefaultSize();
	}

	@Override
	public void encode(Encoder encoder) {
		throw new LowlevelError("Should never save the constant space");
	}

}
