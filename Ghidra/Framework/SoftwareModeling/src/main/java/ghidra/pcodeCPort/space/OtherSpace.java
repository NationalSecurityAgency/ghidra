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

import ghidra.pcodeCPort.translate.Translate;

public class OtherSpace extends AddrSpace {

	public OtherSpace(Translate t, String nm, int ind) {
		super(t, spacetype.IPTR_PROCESSOR, nm, 8, 1, ind, 0, 0);
		clearFlags(heritaged);
		setFlags(is_otherspace);
	}

	public OtherSpace(Translate t) {
		super(t, spacetype.IPTR_PROCESSOR);
		clearFlags(heritaged);
		setFlags(is_otherspace);
	}

	@Override
	public int printRaw(PrintStream s, long offset) {
		s.append("0x");
		s.append(Long.toHexString(offset));
		return getTrans().getDefaultSize();
	}

	@Override
	public void saveXml(PrintStream s) {
		s.print("<space_other");
		save_basic_attributes(s);
		s.println("/>");
	}
}
