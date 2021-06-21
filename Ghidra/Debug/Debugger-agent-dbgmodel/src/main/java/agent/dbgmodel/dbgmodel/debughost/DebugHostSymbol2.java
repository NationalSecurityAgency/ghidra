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

import com.sun.jna.Structure.ByReference;
import com.sun.jna.WString;

/**
 * A wrapper for {@code IDebugHostSymbol2} and its newer variants.
 */
public interface DebugHostSymbol2 extends DebugHostSymbol1 {

	DebugHostSymbolEnumerator enumerateChildrenEx(long kind, WString name, ByReference searchInfo);

	int getLanguage();
}
