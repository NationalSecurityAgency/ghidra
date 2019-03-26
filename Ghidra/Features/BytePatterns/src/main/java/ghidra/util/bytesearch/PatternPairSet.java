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
package ghidra.util.bytesearch;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * Two collections of patterns that are paired together to create larger patterns
 * The final large patterns all must first match a pattern from the "pre" pattern collection
 * followed immediately by a pattern from the "post" pattern collection
 *
 */
public class PatternPairSet {
	private int totalBitsOfCheck;				// Minimum number of bits of check in final patterns
	private int postBitsOfCheck;				// Minimum bits of check in "post" part of pattern
	private ArrayList<DittedBitSequence> preSequences;
	private ArrayList<Pattern> postPatterns;
	
	public PatternPairSet() {
		preSequences = new ArrayList<DittedBitSequence>();
		postPatterns = new ArrayList<Pattern>();
	}
	
	public void createFinalPatterns(ArrayList<Pattern> finalpats) {
		for(int i=0;i<postPatterns.size();++i) {
			Pattern postpattern = postPatterns.get(i);
			int postcheck = postpattern.getNumFixedBits();
			if (postcheck < postBitsOfCheck) {
				continue;
			}
			for(int j=0;j<preSequences.size();++j) {
				DittedBitSequence prepattern = preSequences.get(j);
				int precheck = prepattern.getNumFixedBits();
				if (precheck + postcheck < totalBitsOfCheck) {
					continue;
				}
				DittedBitSequence concat = prepattern.concatenate(postpattern);
				Pattern finalpattern = new Pattern(concat,prepattern.getSize(),postpattern.getPostRules(),postpattern.getMatchActions());
				finalpats.add(finalpattern);
			}
		}
	}
	
	public void extractPostPatterns(ArrayList<Pattern> postpats) {
		for(int i=0;i<postPatterns.size();++i) {
			postpats.add(postPatterns.get(i));
		}
	}
	
	public void restoreXml(XmlPullParser parser,PatternFactory pfactory) throws IOException {
		XmlElement el = parser.start("patternpairs");
		totalBitsOfCheck = SpecXmlUtils.decodeInt(el.getAttribute("totalbits"));
		postBitsOfCheck = SpecXmlUtils.decodeInt(el.getAttribute("postbits"));
		parser.start("prepatterns");
		el= parser.peek();
		while(el.isStart()) {
			DittedBitSequence preseq = new DittedBitSequence();
			preseq.restoreXmlData(parser);
			preSequences.add(preseq);
			el = parser.peek();
		}
		parser.end();
		while(parser.peek().isStart()) {
			parser.start("postpatterns");
			el = parser.peek();
			ArrayList<DittedBitSequence> postdit = new ArrayList<DittedBitSequence>();
			while(el.isStart() && el.getName().equals("data")) {
				DittedBitSequence postseq = new DittedBitSequence();
				postseq.restoreXmlData(parser);
				if (postseq.getNumFixedBits() >= postBitsOfCheck) {
					postdit.add(postseq);
				}
				el = parser.peek();
			}
			ArrayList<PostRule> postRuleArray = new ArrayList<PostRule>();
			ArrayList<MatchAction> matchActionArray = new ArrayList<MatchAction>();
			if (pfactory != null) {
				Pattern.restoreXmlAttributes(postRuleArray, matchActionArray, parser, pfactory);
			}
			PostRule[] postRules = new PostRule[postRuleArray.size()];
			postRuleArray.toArray(postRules);
			MatchAction[] matchActions = new MatchAction[matchActionArray.size()];
			matchActionArray.toArray(matchActions);
			for(int i=0;i<postdit.size();++i) {
				Pattern postpat = new Pattern(postdit.get(i),0,postRules,matchActions);
				postPatterns.add(postpat);
			}
			parser.end();	// End postpatterns
		}
		parser.end();   // End patternlist
	}

	/**
	 * Get the "pre" parts of the patterns
	 * @return pre sequences
	 */
	public ArrayList<DittedBitSequence> getPreSequences() {
		return preSequences;
	}

	/**
	 * Get the "post" parts of the patterns
	 * @return post patterns
	 */
	public ArrayList<Pattern> getPostPatterns() {
		return postPatterns;
	}

	/**
	 * Get the required number of fixed bits after the prepattern
	 * @return number of post bits
	 */
	public int getPostBitsOfCheck() {
		return postBitsOfCheck;
	}

	/**
	 * Get the required number of fixed bits in the whole pattern
	 * @return number of total fixed bits
	 */
	public int getTotalBitsOfCheck() {
		return totalBitsOfCheck;
	}

}
