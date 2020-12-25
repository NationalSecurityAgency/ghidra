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

import java.io.*;
import java.util.ArrayList;

import org.xml.sax.*;

import generic.jar.ResourceFile;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

/**
 * Pattern is an association of a DittedBitSequence to match,
 * a set of post rules after a match is found that must be satisfied,
 * and a set of actions to be taken if the pattern matches.
 * 
 * These patterns can be restored from an XML file.
 */
public class Pattern extends DittedBitSequence {

	private int markOffset;	// Within pattern what is the 'marked' byte
	private PostRule[] postrule;
	private MatchAction[] actions;

	/**
	 * Construct an empty pattern.  Use XML to initialize
	 */
	public Pattern() {
		markOffset = 0;
		postrule = null;
		actions = null;

	}

	/**
	 * Construct the pattern based on a DittedByteSequence a match offset, post matching rules,
	 * and a set of actions to take when the match occurs.
	 * 
	 * @param seq DittedByteSequence
	 * @param offset offset from the actual match location to report a match
	 * @param postArray post set of rules to check for the match
	 * @param matchArray MatchActions to apply when a match occurs
	 */
	public Pattern(DittedBitSequence seq, int offset, PostRule[] postArray,
			MatchAction[] matchArray) {
		super(seq);
		markOffset = offset;
		postrule = postArray;
		actions = matchArray;
	}

	public PostRule[] getPostRules() {
		return postrule;
	}

	public MatchAction[] getMatchActions() {
		return actions;
	}

	public void setMatchActions(MatchAction[] actions) {
		this.actions = actions;
	}

	public int getMarkOffset() {
		return markOffset;
	}

	/**
	 * Restore the PostRule and the MatchAction tags
	 * @param parser is the parser at the start of tags
	 * @param pfactory is the factory for the PostRule and MatchAction objects
	 * @throws IOException
	 */
	public static void restoreXmlAttributes(ArrayList<PostRule> postrulelist,
			ArrayList<MatchAction> actionlist, XmlPullParser parser, PatternFactory pfactory)
			throws IOException {
		XmlElement el = parser.peek();
		while (el.isStart()) {
			PostRule newrule = pfactory.getPostRuleByName(el.getName());
			if (newrule != null) {
				newrule.restoreXml(parser);
				postrulelist.add(newrule);
			}
			else {
				MatchAction matchaction = pfactory.getMatchActionByName(el.getName());
				if (matchaction != null) {
					matchaction.restoreXml(parser);
					actionlist.add(matchaction);
				}
				else {
					throw new IOException("Bad <pattern> subtag");
				}
			}
			el = parser.peek();
		}

	}

	public void restoreXml(XmlPullParser parser, PatternFactory pfactory) throws IOException {
		markOffset = 0;
		ArrayList<PostRule> postrulelist = new ArrayList<PostRule>();
		ArrayList<MatchAction> actionlist = new ArrayList<MatchAction>();
		XmlElement el = parser.start("pattern");
		String markstring = el.getAttribute("mark");
		if (markstring != null) {
			markOffset = SpecXmlUtils.decodeInt(markstring);
		}
		int moff = restoreXmlData(parser);			// Restore data portion of the tag
		if (moff >= 0) {
			markOffset = moff;
		}
		if (pfactory != null) {
			restoreXmlAttributes(postrulelist, actionlist, parser, pfactory);
		}
		parser.end();
		actions = new MatchAction[actionlist.size()];
		actionlist.toArray(actions);
		postrule = new PostRule[postrulelist.size()];
		postrulelist.toArray(postrule);

	}

	/**
	 * Read patterns from specified file
	 * @param file pattern file
	 * @param patlist list for patterns to be added to
	 * @param pfactory optional factory for use in parsing PostRule and MatchAction elements.  
	 * If null such elements may not be present.
	 * @throws SAXException
	 * @throws IOException
	 */
	public static void readPatterns(ResourceFile file, ArrayList<Pattern> patlist,
			PatternFactory pfactory) throws SAXException, IOException {
		ErrorHandler handler = new ErrorHandler() {
			@Override
			public void error(SAXParseException exception) throws SAXException {
				throw new SAXException("Error: " + exception);
			}

			@Override
			public void fatalError(SAXParseException exception) throws SAXException {
				throw new SAXException("Fatal error: " + exception);
			}

			@Override
			public void warning(SAXParseException exception) throws SAXException {
				throw new SAXException("Warning: " + exception);
			}
		};
		XmlPullParser parser;
		try (InputStream inputStream = file.getInputStream()) {
			parser = new NonThreadedXmlPullParserImpl(inputStream, file.getName(), handler, false);
		}
		parser.start("patternlist");
		XmlElement el = parser.peek();
		while (el.isStart()) {
			if (el.getName().equals("patternpairs")) {
				PatternPairSet pairset = new PatternPairSet();
				pairset.restoreXml(parser, pfactory);
				pairset.createFinalPatterns(patlist);
			}
			else {
				Pattern pat = new Pattern();
				pat.restoreXml(parser, pfactory);
				patlist.add(pat);
			}
			el = parser.peek();
		}
		parser.end();
	}

	/**
	 * Read just the post patterns from the <patternpair> tags
	 * @param file is the file to read from
	 * @param patternList collects the resulting Pattern objects
	 * @param pfactory is the factory for constructing postrules and matchactions
	 * @throws IOException 
	 * @throws SAXException 
	 */
	public static void readPostPatterns(File file, ArrayList<Pattern> patternList,
			PatternFactory pfactory) throws SAXException, IOException {
		ErrorHandler handler = new ErrorHandler() {
			@Override
			public void error(SAXParseException exception) throws SAXException {
				throw new SAXException("Error: " + exception);
			}

			@Override
			public void fatalError(SAXParseException exception) throws SAXException {
				throw new SAXException("Fatal error: " + exception);
			}

			@Override
			public void warning(SAXParseException exception) throws SAXException {
				throw new SAXException("Warning: " + exception);
			}
		};
		XmlPullParser parser = new NonThreadedXmlPullParserImpl(file, handler, false);
		parser.start("patternlist");
		XmlElement el = parser.peek();
		while (el.isStart()) {
			if (el.getName().equals("patternpairs")) {
				PatternPairSet pairset = new PatternPairSet();
				pairset.restoreXml(parser, pfactory);
				pairset.extractPostPatterns(patternList);
			}
			else {
				parser.next();
			}
			el = parser.peek();
		}
		parser.end();

	}
}
