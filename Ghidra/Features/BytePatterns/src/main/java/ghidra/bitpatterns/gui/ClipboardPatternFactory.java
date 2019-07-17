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
package ghidra.bitpatterns.gui;

import ghidra.app.analyzers.FunctionStartAnalyzer;
import ghidra.util.bytesearch.*;

/**
 * This class is an implementation of the PatternFactory interface for use by {@link ClipboardPanel}
 */
public class ClipboardPatternFactory implements PatternFactory {

	private DummyMatchAction dummyAction;

	/**
	 * Create a new ClipboardPatternFactory
	 */
	public ClipboardPatternFactory() {
		dummyAction = new DummyMatchAction();
	}

	@Override
	public MatchAction getMatchActionByName(String nm) {
		if (nm.equals("setcontext")) {
			FunctionStartAnalyzer funcAnalyzer = new FunctionStartAnalyzer();
			return funcAnalyzer.new ContextAction();
		}
		return dummyAction;
	}

	@Override
	public PostRule getPostRuleByName(String nm) {
		if (nm.equals("align")) {
			return new AlignRule();
		}
		return null;
	}

}
