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
package ghidra.dbg.sctl.protocol.consts;

import ghidra.comm.util.BitmaskUniverse;

/**
 * See the SCTL documentation
 */
public enum Stype implements BitmaskUniverse {
	Sundef(1 << 0), Sdata(1 << 1), Stext(1 << 2), Sro(1 << 3), Senum(1 << 4), Sinline(1 << 5);

	public final long mask;

	private Stype(long mask) {
		this.mask = mask;
	}

	@Override
	public long getMask() {
		return mask;
	}
}
