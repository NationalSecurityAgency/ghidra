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
package org.elasticsearch.plugin.analysis.lsh;

import java.util.*;

import org.elasticsearch.script.*;

public class BSimScriptEngine implements ScriptEngine {
	private final static String ENGINE_NAME = "bsim_scripts";

	@Override
	public <FactoryType> FactoryType compile(String scriptName, String scriptSource,
			ScriptContext<FactoryType> context, Map<String, String> params) {
		if (context.equals(ScoreScript.CONTEXT) == false) {
			throw new IllegalArgumentException(
				getType() + "scripts cannot be used for context [" + context.name + "]");
		}
		if (VectorCompareScriptFactory.SCRIPT_NAME.equals(scriptSource)) {
			ScoreScript.Factory factory = new VectorCompareScriptFactory();
			return context.factoryClazz.cast(factory);
		}
		throw new IllegalArgumentException("Unknown script name " + scriptSource);
	}

	@Override
	public void close() {
		// Can free up resources
	}

	@Override
	public Set<ScriptContext<?>> getSupportedContexts() {
		return Collections.singleton(ScoreScript.CONTEXT);
	}

	@Override
	public String getType() {
		return ENGINE_NAME;
	}

}
