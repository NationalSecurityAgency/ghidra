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
 * A set of "pre" DittedBitSequences and a set of "post" Patterns are paired to form a larger pattern.
 * To match, a sequence from the "pre" sequence set must first match, then one of the "post" patterns
 * is matched relative to the matching "pre" pattern.  This class is really a storage object for the
 * patterns and provides a mechanism to read the pre/post patterns from an XML file.
 *
 * The larger pattern has the idea of bits of check, which means the number of bits that are fixed to
 * a value when matching (not don't care).  There is a pre pattern bits of check and post pattern bits
 * of check.  The bits of check are used to statistically gauge the accuracy of the pattern.
 * 
 * An example of the XML format follows:
 *   <patternpairs totalbits="32" postbits="16">
 *    <prepatterns>
 *      <data>0xe12fff1.                  </data>
 *      <data>0xe12fff1e 0x46c0           </data>
 *      <data>0xe12fff1e 0xe1a00000       </data>
 *    </prepatterns>
 *    
 *  <postpatterns>
 *      <data> 0xe24dd...                              11101001 00101101 .1...... ....0000  </data>
 *      <data> 11101001 00101101 .1...... ....0000     0xe24dd...                           </data>
 *      <data> 11101001 00101101 .1...... ....0000     0x........ 0xe24dd...                </data>
 *      <align mark="0" bits="3"/>
 *      <setcontext name="TMode" value="0"/>
 *      <funcstart/>
 *    </postpatterns>
 *  </patternpairs>
 *  
 *  Note: The post Patterns can also have a set of rules that must be satisfied along with one of the
 *  Pattern DittedBitSequence matches.
 */
public class PatternPairSet {
	private int totalBitsOfCheck;				// Minimum number of bits of check in final patterns
	private int postBitsOfCheck;				// Minimum bits of check in "post" part of pattern
	private ArrayList<DittedBitSequence> preSequences;
	private ArrayList<Pattern> postPatterns;

	/**
	 * Construct an empty PatternPairSet.  Use XML to initialize the pattern sets.
	 */
	public PatternPairSet() {
		preSequences = new ArrayList<DittedBitSequence>();
		postPatterns = new ArrayList<Pattern>();
	}

	public void createFinalPatterns(ArrayList<Pattern> finalpats) {
		for (int i = 0; i < postPatterns.size(); ++i) {
			Pattern postpattern = postPatterns.get(i);
			int postcheck = postpattern.getNumFixedBits();
			if (postcheck < postBitsOfCheck) {
				continue;
			}
			for (DittedBitSequence prepattern : preSequences) {
				int precheck = prepattern.getNumFixedBits();
				if (precheck + postcheck < totalBitsOfCheck) {
					continue;
				}
				DittedBitSequence concat = prepattern.concatenate(postpattern);
				Pattern finalpattern = new Pattern(concat, prepattern.getSize(),
					postpattern.getPostRules(), postpattern.getMatchActions());
				finalpats.add(finalpattern);
			}
		}
	}

	/**
	 * Add this PatternPairSets post patterns to an existing arraylist of patterns.
	 * @param postpats array to add this PatternPairSets post patterns into
	 */
	public void extractPostPatterns(ArrayList<Pattern> postpats) {
		for (int i = 0; i < postPatterns.size(); ++i) {
			postpats.add(postPatterns.get(i));
		}
	}

	/**
	 * Restore PatternPairSet from XML pull parser
	 * @param parser XML pull parser
	 * @param pfactory pattern factory user to construct patterns
	 * @throws IOException if pull parsing fails
	 */
	public void restoreXml(XmlPullParser parser, PatternFactory pfactory) throws IOException {
		XmlElement el = parser.start("patternpairs");
		totalBitsOfCheck = SpecXmlUtils.decodeInt(el.getAttribute("totalbits"));
		postBitsOfCheck = SpecXmlUtils.decodeInt(el.getAttribute("postbits"));
		parser.start("prepatterns");
		el = parser.peek();
		while (el.isStart()) {
			DittedBitSequence preseq = new DittedBitSequence();
			preseq.restoreXmlData(parser);
			preSequences.add(preseq);
			el = parser.peek();
		}
		parser.end();
		while (parser.peek().isStart()) {
			parser.start("postpatterns");
			el = parser.peek();
			ArrayList<DittedBitSequence> postdit = new ArrayList<DittedBitSequence>();
			while (el.isStart() && el.getName().equals("data")) {
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
			for (DittedBitSequence element : postdit) {
				Pattern postpat = new Pattern(element, 0, postRules, matchActions);
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
