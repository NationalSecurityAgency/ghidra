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
package agent.dbgeng.model.iface1;

import agent.dbgeng.model.iface2.DbgModelTargetObject;
import ghidra.dbg.target.TargetEnvironment;

public interface DbgModelTargetEnvironment extends DbgModelTargetObject, TargetEnvironment {

	public void refreshInternal();

	@Override
	public default String getArchitecture() {
		return getTypedAttributeNowByName(ARCH_ATTRIBUTE_NAME, String.class, "");
	}

	@Override
	public default String getDebugger() {
		return getTypedAttributeNowByName(DEBUGGER_ATTRIBUTE_NAME, String.class, "");
	}

	@Override
	public default String getOperatingSystem() {
		return getTypedAttributeNowByName(OS_ATTRIBUTE_NAME, String.class, "");
	}

}
