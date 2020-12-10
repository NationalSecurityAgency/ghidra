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

/**
 * See the SCTL documentation
 */
public enum Tkind {
	Tvoid("void"),
	Tbase("base"),
	Tstruct("struct"),
	Tunion("union"),
	Tenum("enum"),
	Tptr("pointer"),
	Tarr("array"),
	Tfun("function"),
	Ttypedef("typedef"),
	Tbitfield("bitfield"),
	Tconst("constant"),
	Txaccess("xaccess"),
	Tundef("undef");

	private String str;

	Tkind(String str) {
		this.str = str;
	}

	@Override
	public String toString() {
		return "Tkind:" + str;
	}
}
