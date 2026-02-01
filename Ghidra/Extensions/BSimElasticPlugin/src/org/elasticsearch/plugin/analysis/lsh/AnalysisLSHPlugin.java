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

import java.io.IOException;
import java.util.*;

import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;
import org.elasticsearch.index.IndexModule;
import org.elasticsearch.index.IndexSettings;
import org.elasticsearch.index.analysis.TokenizerFactory;
import org.elasticsearch.indices.analysis.AnalysisModule.AnalysisProvider;
import org.elasticsearch.plugins.*;
import org.elasticsearch.script.ScriptContext;
import org.elasticsearch.script.ScriptEngine;

import generic.lsh.vector.IDFLookup;
import generic.lsh.vector.WeightFactory;
import ghidra.features.bsim.query.elastic.Base64VectorFactory;
import ghidra.features.bsim.query.elastic.ElasticUtilities;

public class AnalysisLSHPlugin extends Plugin implements AnalysisPlugin, ScriptPlugin {

	public static final String TOKENIZER_SETTINGS_BASE = "index.analysis.tokenizer.lsh_";
	public static String settingString = "";

	static private Map<String, Base64VectorFactory> vecFactoryMap = new HashMap<>();
	private Map<String, AnalysisProvider<TokenizerFactory>> tokFactoryMap;

	public class TokenizerFactoryProvider implements AnalysisProvider<TokenizerFactory> {

		@Override
		public TokenizerFactory get(IndexSettings indexSettings, Environment env, String name,
				Settings settings) throws IOException {
//			settingString = settingString + " : " + indexSettings.getIndex().getName() + '(' + name + ')';
			return new LSHTokenizerFactory(indexSettings, env, name, settings);
		}
	}

	public AnalysisLSHPlugin() {
		TokenizerFactoryProvider provider = new TokenizerFactoryProvider();
		tokFactoryMap = Collections.singletonMap("lsh_tokenizer", provider);
	}

	private static void setupVectorFactory(String name, String idfConfig, String lshWeights) {
		WeightFactory weightFactory = new WeightFactory();
		String[] split = lshWeights.split(" ");
		double[] weightArray = new double[split.length];
		for (int i = 0; i < weightArray.length; ++i) {
			weightArray[i] = Double.parseDouble(split[i]);
		}
		weightFactory.set(weightArray);
		IDFLookup idfLookup = new IDFLookup();
		split = idfConfig.split(" ");
		int[] intArray = new int[split.length];
		for (int i = 0; i < intArray.length; ++i) {
			intArray[i] = Integer.parseInt(split[i]);
		}
		idfLookup.set(intArray);
		Base64VectorFactory vectorFactory = new Base64VectorFactory();
		// Server-side factory is never used to generate signatures,
		//   so we don't need to specify settings
		vectorFactory.set(weightFactory, idfLookup, 0);
		vecFactoryMap.put(name, vectorFactory);
	}

	/**
	 * Entry point for Tokenizer and Script factories to grab the global vector factory
	 * @param name is the name of the tokenizer
	 * @return the vector factory used by the tokenizer
	 */
	public static Base64VectorFactory getVectorFactory(String name) {
		return vecFactoryMap.get(name);
	}

	@Override
	public void onIndexModule(IndexModule indexModule) {
		super.onIndexModule(indexModule);

		Settings settings = indexModule.getSettings();
		String name = null;
		// Look for the specific kind of tokenizer settings, within the global settings for the index
		for (String key : settings.keySet()) {
			if (key.startsWith(TOKENIZER_SETTINGS_BASE)) {
				// We can have different settings for different indices, distinguished by this name
				int pos = key.indexOf('.', TOKENIZER_SETTINGS_BASE.length() + 1);
				if (pos > 0) {
					name = key.substring(TOKENIZER_SETTINGS_BASE.length(), pos);
					break;
				}
			}
		}
		if (name != null) {
			String tokenizerName = "lsh_" + name;
			if (getVectorFactory(tokenizerName) != null) {
				return;		// Factory already exists
			}
			settingString = settingString + " : onModule(" + name + ')';
			// If we found LSH tokenizer settings, pull them out and construct an LSHVectorFactory with them
			String baseKey = TOKENIZER_SETTINGS_BASE + name + '.';
			String idfConfig = settings.get(baseKey + ElasticUtilities.IDF_CONFIG);
			String lshWeights = settings.get(baseKey + ElasticUtilities.LSH_WEIGHTS);
			if (idfConfig == null || lshWeights == null) {
				return;		// IDF_CONFIG and LSH_WEIGHTS settings must be present to proceed
			}
			setupVectorFactory(tokenizerName, idfConfig, lshWeights);
		}
	}

	@Override
	public ScriptEngine getScriptEngine(Settings settings, Collection<ScriptContext<?>> contexts) {
		return new BSimScriptEngine();
	}

	@Override
	public Map<String, AnalysisProvider<TokenizerFactory>> getTokenizers() {
		return tokFactoryMap;
	}

}
