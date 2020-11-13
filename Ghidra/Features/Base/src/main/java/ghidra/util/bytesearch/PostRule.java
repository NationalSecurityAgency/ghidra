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

import ghidra.xml.XmlPullParser;

/**
 * Inteface for post match rules that are checked after a match is idenfied
 */
public interface PostRule {
	/**
	 * Apply a post rule given the matching pattern and offset into the byte stream.
	 * @param pat pattern that matched
	 * @param matchoffset offset of the match
	 * @return true if the PostRule is satisfied
	 */
	public boolean apply(Pattern pat, long matchoffset);

	/**
	 * Can restore state of instance PostRule from XML
	 * 
	 * @param parser XML pull parser
	 */
	public void restoreXml(XmlPullParser parser);
}
