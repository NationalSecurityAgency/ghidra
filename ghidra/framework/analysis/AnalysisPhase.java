/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.framework.analysis;

import ghidra.app.services.Analyzer;

import org.jdom.Element;

public class AnalysisPhase implements Comparable<AnalysisPhase> {
	static final String XML_ELEMENT_NAME = "ANALYSIS_PHASE";

	private AnalysisRecipe recipe;
	private int index;
	private boolean isCheckPoint;

	public AnalysisPhase(AnalysisRecipe recipe, int index, boolean isCheckPoint) {
		this.recipe = recipe;
		this.index = index;
		this.isCheckPoint = isCheckPoint;
	}

	AnalysisPhase(Element element) {
		this.index = Integer.parseInt(element.getAttributeValue("INDEX"));
		this.isCheckPoint = Boolean.parseBoolean(element.getAttributeValue("CHECKPOINT"));
	}

	@Override
	final public boolean equals(Object obj) {
		return this == obj;
	}

	@Override
	final public int hashCode() {
		return super.hashCode();
	}

	@Override
	public String toString() {
		return getName();
	}

	public String getName() {
		return Integer.toString(index + 1);
	}

	public Element toXML() {
		Element element = new Element(XML_ELEMENT_NAME);
		element.setAttribute("INDEX", Integer.toString(index));
		element.setAttribute("CHECKPOINT", Boolean.toString(isCheckPoint));
		return element;
	}

	public int getIndex() {
		return index;
	}

	void setIndex(int i) {
		index = i;
	}

	public boolean isEnabled(Analyzer analyzer) {
		return recipe.isAnalyzerEnabled(analyzer);
	}

	public AnalysisPhase getExecutionPhase(Analyzer analyzer) {
		return recipe.getExecutionPhase(analyzer, this);
	}

	@Override
	public int compareTo(AnalysisPhase o) {
		return index - o.index;
	}

	public boolean isCheckPoint() {
		return isCheckPoint;
	}

	public void setIsCheckPoint(boolean b) {
		if (recipe.getLastPhase() == this) {
			return;  // can't change state of last phase - it is always a checkpoint
		}
		this.isCheckPoint = b;
	}
}
