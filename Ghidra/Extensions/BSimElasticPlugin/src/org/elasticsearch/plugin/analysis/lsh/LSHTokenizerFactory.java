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

import org.apache.lucene.analysis.Tokenizer;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;
import org.elasticsearch.index.IndexSettings;
import org.elasticsearch.index.analysis.AbstractTokenizerFactory;

import ghidra.features.bsim.query.elastic.Base64VectorFactory;
import ghidra.features.bsim.query.elastic.ElasticUtilities;

public class LSHTokenizerFactory extends AbstractTokenizerFactory {

	private Base64VectorFactory vectorFactory;
	private int k;
	private int L;

	public LSHTokenizerFactory(IndexSettings indexSettings, Environment environment, String name, Settings settings) {
		super(indexSettings, settings, name);
		k = settings.getAsInt(ElasticUtilities.K_SETTING, -1);
		L = settings.getAsInt(ElasticUtilities.L_SETTING, -1);
		vectorFactory = AnalysisLSHPlugin.getVectorFactory(name);
	}

	@Override
	public Tokenizer create() {
		return new LSHTokenizer(k,L,vectorFactory);
	}
}
