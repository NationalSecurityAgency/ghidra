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

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.xml.XmlPullParser;

/**
 * Interface for a match action to be taken for the Program@Address for a ditted bit seqence pattern
 */
public interface MatchAction {
	/**
	 * Apply the match action to the program at the address.
	 * 
	 * @param program program in which the match occurred
	 * @param addr where the match occured
	 * @param match information about the match that occurred
	 */
	public void apply(Program program, Address addr, Match match);

	/**
	 * Action can be constructed from XML
	 * 
	 * @param parser XML pull parser to restore action from XML
	 */
	public void restoreXml(XmlPullParser parser);
}
