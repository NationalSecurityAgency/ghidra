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

import org.apache.lucene.analysis.Tokenizer;
import org.apache.lucene.analysis.tokenattributes.CharTermAttribute;
import org.elasticsearch.plugin.analysis.lsh.LSHBinner.BytesRef;

import generic.lsh.vector.LSHVector;
import ghidra.features.bsim.query.elastic.Base64VectorFactory;

public class LSHTokenizer extends Tokenizer {
    private final CharTermAttribute bytesAtt = addAttribute(CharTermAttribute.class);
    private BytesRef[] tokens;
    private int pos;				// Number of terms/tokens returned so far
    private Base64VectorFactory vectorFactory;
    private LSHBinner binner;
    private char[] vecBuffer;

    public LSHTokenizer(int k,int L,Base64VectorFactory vFactory) {
    	super(DEFAULT_TOKEN_ATTRIBUTE_FACTORY);
    	vectorFactory = vFactory;
    	binner = new LSHBinner();
    	binner.setKandL(k, L);
    	pos = -1;
    	vecBuffer = Base64VectorFactory.allocateBuffer();
    }

	@Override
	public boolean incrementToken() throws IOException {
		clearAttributes();
		if (pos < 0) {
			LSHVector vector = vectorFactory.restoreVectorFromBase64(input,vecBuffer);
//			AnalysisLSHPlugin.settingString = AnalysisLSHPlugin.settingString + " : " + Long.toHexString(vector.calcUniqueHash());
			binner.generateBinIds(vector.getEntries());
			tokens = binner.getTokenList();
			pos = 0;
		}
		if (pos < tokens.length) {
			char[] buffer = tokens[pos].buffer;
			bytesAtt.copyBuffer(buffer,0,buffer.length);
			pos += 1;
			return true;
		}
		return false;
	}

	@Override
	public void reset() throws IOException {
		super.reset();
		pos = -1;
	}
}
