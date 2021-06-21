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
import agent.dbgmodel.dbgmodel.main.ModelObject;

/**
 * A wrapper for {@code IDebugHostEvaluator1} and its newer variants.
 */
public interface DebugHostEvaluator1 extends UnknownEx {

	ModelObject evaluateExpression(DebugHostContext context, WString expression,
			ModelObject bindingContext);

	ModelObject evaluateExtendedExpression(DebugHostContext context, WString expression,
			ModelObject bindingContext);

}
