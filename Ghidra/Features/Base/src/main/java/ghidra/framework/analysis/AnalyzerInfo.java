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
package ghidra.framework.analysis;

import org.jdom.Element;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.services.*;

class AnalyzerInfo implements Comparable<AnalyzerInfo> {
	static final String XML_ELEMENT_NAME = "ANALYZER";
	static final String CLASS_NAME = "CLASS_NAME";

	private boolean enabled;
	private final boolean defaultEnablement;
	private Analyzer analyzer;
	private AnalysisPriority analysisPriority;
	private AnalysisPhase startPhase;
	private AnalysisRecipe recipe;

	AnalyzerInfo(AnalysisRecipe analysisRecipe, Analyzer analyzer, boolean defaultEnablement) {
		this.recipe = analysisRecipe;
		this.analyzer = analyzer;
		this.startPhase = recipe.getLastPhase();
		this.analysisPriority = analyzer.getPriority();
		this.defaultEnablement = defaultEnablement;
		this.enabled = defaultEnablement;
	}

	@Override
	public int compareTo(AnalyzerInfo o) {
		// first make all One-Shot Analyzers sort before all other types.
		AnalyzerType myType = analyzer.getAnalysisType();
		AnalyzerType otherType = o.analyzer.getAnalysisType();
		if (myType == AnalyzerType.ONE_SHOT_ANALYZER &&
			otherType != AnalyzerType.ONE_SHOT_ANALYZER) {
			return -1;
		}
		if (myType != AnalyzerType.ONE_SHOT_ANALYZER &&
			otherType == AnalyzerType.ONE_SHOT_ANALYZER) {
			return 1;
		}

		int diff = analysisPriority.priority() - o.analysisPriority.priority();
		if (diff == 0) {
			return analyzer.getName().compareTo(o.analyzer.getName());
		}
		return diff;
	}

	public void setEnabled(boolean b) {
		enabled = b;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public AnalysisPhase getNextEnabledPhaseAtOrAfter(AnalysisPhase phase) {
		if (!enabled) {
			return null;
		}
		// if the given phase is less than the start phase, report the start phase
		if (phase.compareTo(startPhase) <= 0) {
			return startPhase;
		}

		if (analyzer.getAnalysisType() == AnalyzerType.ONE_SHOT_ANALYZER) {
			// one shots only run once, so return null for all phases after start phase
			return null;
		}
		// all other analyzers will run in all phases at or after their start phase.
		return phase;
	}

	public Analyzer getAnalyzer() {
		return analyzer;
	}

	public void setStartPhase(AnalysisPhase phase) {
		this.startPhase = phase;
	}

	Element toXML() {
		Element element = new Element(XML_ELEMENT_NAME);
		element.setAttribute(CLASS_NAME, analyzer.getClass().getName());
		if (analyzer instanceof GhidraScriptAnalyzerAdapter) {
			GhidraScriptAnalyzerAdapter wrappedAnalyzer = (GhidraScriptAnalyzerAdapter) analyzer;
			element.setAttribute("SCRIPT_NAME", wrappedAnalyzer.getScriptName());
			element.setAttribute("ANALYZER_TYPE", wrappedAnalyzer.getAnalysisType().name());
			element.setAttribute("PRIORITY",
				Integer.toString(wrappedAnalyzer.getPriority().priority()));
		}
		element.setAttribute("START_PHASE", Integer.toString(startPhase.getIndex()));
		if (enabled != defaultEnablement) {
			element.setAttribute("ENABLED", Boolean.toString(enabled));
		}
		return element;
	}

	void loadFromXML(Element element) {
		String enabledValue = element.getAttributeValue("ENABLED");  // defaults are not saved, so could be null
		if (enabledValue != null) {
			enabled = Boolean.parseBoolean(enabledValue);
		}
		int startPhaseIndex = Integer.parseInt(element.getAttributeValue("START_PHASE"));
		startPhase = recipe.getPhase(startPhaseIndex);
	}

	public AnalysisPhase getAnalyzerStartPhase() {
		return startPhase;
	}

	public static AnalyzerInfo createInfoForWrappedAnalzyer(AnalysisRecipe recipe,
			Element element) {
		String scriptName = element.getAttributeValue("SCRIPT_NAME");
		String type = element.getAttributeValue("ANALYZER_TYPE");
		AnalyzerType analyzerType = AnalyzerType.valueOf(type);
		int priority = Integer.parseInt(element.getAttributeValue("PRIORITY"));
		ResourceFile file = GhidraScriptUtil.findScriptByName(scriptName);
		Analyzer analyzer = new GhidraScriptAnalyzerAdapter(file, analyzerType, priority);
		return new AnalyzerInfo(recipe, analyzer, true);
	}
}
