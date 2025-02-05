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
package ghidra.app.plugin.core.debug.client.tracermi;

import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.RegisterValue;

public class DefaultRegisterMapper implements RegisterMapper {
	
	public DefaultRegisterMapper(LanguageID id) {
		// Nothing so far
	}

	@Override
	public String mapName(String name) {
		return name;
	}

	@Override
	public String mapNameBack(String name) {
		return name;
	}

	@Override
	public RegisterValue mapValue(String name, RegisterValue rv) {
		return rv;
	}

	@Override
	public RegisterValue mapValueBack(String name, RegisterValue rv) {
		return rv;
	}


}
