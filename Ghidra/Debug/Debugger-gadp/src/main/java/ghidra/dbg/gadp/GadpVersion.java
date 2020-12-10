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
package ghidra.dbg.gadp;

import java.util.NoSuchElementException;

import ghidra.dbg.gadp.protocol.Gadp;

public enum GadpVersion {
	VER1 {
		@Override
		public String getName() {
			return "gadp1";
		}
	};

	public static Gadp.ConnectRequest.Builder makeRequest() {
		Gadp.ConnectRequest.Builder req = Gadp.ConnectRequest.newBuilder();
		for (GadpVersion ver : values()) {
			req.addVersion(ver.getName());
		}
		return req;
	}

	public static GadpVersion getByName(String name) {
		for (GadpVersion ver : values()) {
			if (name.equals(ver.getName())) {
				return ver;
			}
		}
		throw new NoSuchElementException("Unknown version: " + name);
	}

	public abstract String getName();
}
