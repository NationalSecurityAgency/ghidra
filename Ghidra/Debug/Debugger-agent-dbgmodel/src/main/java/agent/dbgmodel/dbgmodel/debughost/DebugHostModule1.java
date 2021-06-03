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

import agent.dbgmodel.jna.dbgmodel.DbgModelNative.LOCATION;

/**
 * A wrapper for {@code IDebugHostModule1} and its newer variants.
 */
public interface DebugHostModule1 extends DebugHostBase {

	String getImageName(boolean allowPath);

	LOCATION getBaseLocation();

	void getVersion();

	DebugHostType1 findTypeByName(String typeName);

	DebugHostSymbol1 findSymbolByRVA(long rva);

	DebugHostSymbol1 findSymbolByName(String symbolName);

	DebugHostSymbol1 asSymbol();

}
