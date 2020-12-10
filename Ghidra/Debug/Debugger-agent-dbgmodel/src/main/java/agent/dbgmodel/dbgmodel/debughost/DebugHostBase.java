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
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.SymbolKind;
import agent.dbgmodel.jna.dbgmodel.debughost.IDebugHostBaseClass;

/**
 * A wrapper for {@code IDebugHostBase} and its newer variants.
 */
public interface DebugHostBase extends UnknownEx {

	DebugHostContext getContext();

	DebugHostSymbolEnumerator enumerateChildren(SymbolKind symbolModule, WString Name);

	SymbolKind getSymbolKind();

	String getName();

	DebugHostType1 getType();

	DebugHostModule1 getContainingModule();

	long getOffset();

	IDebugHostBaseClass getJnaData();

}
