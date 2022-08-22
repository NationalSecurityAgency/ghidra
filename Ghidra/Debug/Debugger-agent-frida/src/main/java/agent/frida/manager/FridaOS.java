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
package agent.frida.manager;

import com.sun.jna.NativeLong;

public enum FridaOS {
	FRIDA_OS_WINDOWS("windows"),
	FRIDA_OS_MACOS("macos"),
	FRIDA_OS_LINUX("linux"),
	FRIDA_OS_IOS("ios"),
	FRIDA_OS_ANDROID("android"),
	FRIDA_OS_FREEBSD("freebsd"),
	FRIDA_OS_QNX("qnx");

	final String str;

	FridaOS(String str) {
		this.str = str;
	}

	@Override
	public String toString() {
		return str;
	}
	
	public static FridaOS getOS(NativeLong state) {
		return FridaOS.values()[state.intValue()];
	}
}
