/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.factory;

import ghidra.framework.data.GhidraToolState;
import ghidra.framework.data.ToolState;
import ghidra.framework.data.ToolStateFactory;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;

public class GhidraToolStateFactory extends ToolStateFactory {
	
	@Override
	protected ToolState doCreateToolState(PluginTool tool, DomainObject domainObject) {
		return new GhidraToolState(tool, domainObject);
	}
}
