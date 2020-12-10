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
public enum Cbase {
	Vundef("undef"),
	Vbool("_Bool"),
	Vchar("char"),
	Vshort("short"),
	Vint("int"),
	Vlong("long"),
	Vvlong("long long"),
	Vuchar("unsigned char"),
	Vushort("unsigned short"),
	Vuint("unsigned int"),
	Vulong("unsigned long"),
	Vuvlong("unsigned long long"),
	Vfloat("float"),
	Vdouble("double"),
	Vlongdouble("long double"),
	Vcomplex("float complex"),
	Vdoublex("double complex"),
	Vlongdoublex("long double complex"),
	Vptr("ptr"),
	Vvoid("void");

	private String cname;

	Cbase(String cname) {
		this.cname = cname;
	}

	@Override
	public String toString() {
		return "Cbase:" + cname;
	}

	public String getCName() {
		return cname;
	}
}
