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
package agent.dbgmodel.dbgmodel.debughost;

import com.sun.jna.WString;

import agent.dbgmodel.dbgmodel.UnknownEx;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.LOCATION;

/**
 * A wrapper for {@code IDebugHostSymbols} and its newer variants.
 */
public interface DebugHostSymbols extends UnknownEx {

	DebugHostModuleSignature createModuleSignature(WString pwszModuleName, WString pwszMinVersion,
			WString pwszMaxVersion);

	DebugHostTypeSignature createTypeSignature(WString signatureSpecification,
			DebugHostModule1 module);

	DebugHostTypeSignature createTypeSignatureForModuleRange(WString signatureSpecification,
			WString pwszModuleName, WString pwszMinVersion, WString pwszMaxVersion);

	DebugHostSymbolEnumerator enumerateModules(DebugHostContext context);

	DebugHostModule1 findModuleByName(DebugHostContext context, String string);

	DebugHostModule1 findModuleByLocation(DebugHostContext context, LOCATION moduleLocation);

	DebugHostType1 getMostDerivedObject(DebugHostContext context, LOCATION location,
			DebugHostType1 objectTypeLOCATION);
}
