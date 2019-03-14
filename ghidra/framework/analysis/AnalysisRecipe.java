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

import generic.jar.ResourceFile;
import ghidra.app.services.Analyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.Program;

import java.util.*;

import javax.swing.event.ChangeListener;

import org.jdom.Element;

public class AnalysisRecipe {
	private List<AnalysisPhase> phases = new ArrayList<AnalysisPhase>();
	private Map<Analyzer, AnalyzerInfo> analyzerMap = new HashMap<Analyzer, AnalyzerInfo>();
	private List<AnalyzerInfo> analyzerInfoList = new ArrayList<AnalyzerInfo>();
	private ToolOptions options = new ToolOptions("Analysis Options");
	private String name;
	private ChangeListener listener;

	public AnalysisRecipe(String name, Collection<Analyzer> analyzers, Program program) {
		this.name = name;
		phases.add(new AnalysisPhase(this, 0, true));
		for (Analyzer analyzer : analyzers) {
			if (!analyzer.canAnalyze(program)) {
				continue;
			}
			boolean defaultEnablement = analyzer.getDefaultEnablement(program);
			AnalyzerInfo info = new AnalyzerInfo(this, analyzer, defaultEnablement);
			analyzerMap.put(analyzer, info);
			analyzerInfoList.add(info);
		}
		Collections.sort(analyzerInfoList);
		for (Analyzer analyzer : analyzers) {
			analyzer.registerOptions(options.getOptions(analyzer.getName()), program);
		}
	}

	public Options getOptions(Analyzer analyzer) {
		return options.getOptions(analyzer.getName());
	}

	public String getName() {
		return name;
	}

	Element toXML() {
		Element root = new Element("Analysis_Recipe");
		root.setAttribute("Name", name);
		for (AnalysisPhase phase : phases) {
			root.addContent(phase.toXML());
		}
		for (AnalyzerInfo info : analyzerMap.values()) {
			root.addContent(info.toXML());
		}
		Element optionsElement = options.getXmlRoot(false);
		root.addContent(optionsElement);
		return root;
	}

	void loadFromXML(Element root) {
		phases.clear();

		this.name = root.getAttributeValue("Name");
		List<?> phaseChildren = root.getChildren(AnalysisPhase.XML_ELEMENT_NAME);
		for (Object object : phaseChildren) {
			Element child = (Element) object;
			phases.add(new AnalysisPhase(child));
		}
		Collections.sort(phases);
		List<?> infoChildren = root.getChildren(AnalyzerInfo.XML_ELEMENT_NAME);
		for (Object object : infoChildren) {
			processAnalyzerInfoElement((Element) object);
		}

		Element optionsElement = root.getChild(ToolOptions.XML_ELEMENT_NAME);

		options = new ToolOptions(optionsElement);
	}

	private void processAnalyzerInfoElement(Element element) {
		String className = element.getAttributeValue(AnalyzerInfo.CLASS_NAME);
		if (GhidraScriptAnalyzerAdapter.class.getName().equals(className)) {
			AnalyzerInfo info = AnalyzerInfo.createInfoForWrappedAnalzyer(this, element);
			info.setStartPhase(getFirstPhase());
			analyzerMap.put(info.getAnalyzer(), info);
			analyzerInfoList.add(info);
			Collections.sort(analyzerInfoList);
		}
		AnalyzerInfo info = findInfoForAnalyzerClass(className);
		if (info != null) {
			info.loadFromXML(element);
		}
	}

	private AnalyzerInfo findInfoForAnalyzerClass(String className) {
		for (AnalyzerInfo info : analyzerInfoList) {
			if (className.equals(info.getAnalyzer().getClass().getName())) {
				return info;
			}
		}
		return null;
	}

	public List<AnalysisPhase> getAnalysisPhases() {
		return phases;
	}

	public AnalysisPhase getLastPhase() {
		return phases.get(phases.size() - 1);
	}

	public AnalysisPhase getFirstPhase() {
		return phases.get(0);
	}

	public AnalysisPhase createPhase() {
		AnalysisPhase newPhase = new AnalysisPhase(this, 0, false);
		phases.add(0, newPhase);
		for (int i = 0; i < phases.size(); i++) {
			phases.get(i).setIndex(i);
		}
		notifyChanged();
		return newPhase;
	}

	public void deletePhase() {
		if (phases.size() <= 1) {
			return;
		}
		AnalysisPhase removedPhase = phases.remove(0);
		AnalysisPhase firstPhase = phases.get(0);

		for (int i = 0; i < phases.size(); i++) {
			phases.get(i).setIndex(i);
		}
		for (AnalyzerInfo info : analyzerInfoList) {
			if (info.getAnalyzerStartPhase() == removedPhase) {
				info.setStartPhase(firstPhase);
			}
		}
		notifyChanged();
	}

	/**
	 * returns a list of all analyzers in priority order.
	 * @return a list of all analyzers in priority order.
	 */
	public List<Analyzer> getAnalyzers() {
		List<Analyzer> list = new ArrayList<Analyzer>(analyzerMap.size());
		for (AnalyzerInfo info : analyzerInfoList) {
			list.add(info.getAnalyzer());
		}
		return list;
	}

	public AnalysisPhase getPhase(int i) {
		return phases.get(i);
	}

//	AnalyzerInfo getAnalyzerInfo(Analyzer analyzer) {
//		return analyzerMap.get(analyzer);
//	}

//	public AnalyzerStatus getAnalyzerStatus(Analyzer analyzer, AnalysisPhase phase) {
//		AnalyzerInfo analyzerInfo = analyzerMap.get(analyzer);
//		return analyzerInfo.getStatus(phase);
//	}

	public boolean isAnalyzerEnabled(Analyzer analyzer) {
		AnalyzerInfo analyzerInfo = analyzerMap.get(analyzer);
		return analyzerInfo.isEnabled();
	}

	public AnalysisPhase getExecutionPhase(Analyzer analyzer, AnalysisPhase currentPhase) {
		AnalyzerInfo analyzerInfo = analyzerMap.get(analyzer);
		return analyzerInfo.getNextEnabledPhaseAtOrAfter(currentPhase);
	}

//	public void setAnalyzerStatus(Analyzer analyzer, AnalysisPhase phase, AnalyzerStatus status) {
//		AnalyzerInfo info = analyzerMap.get(analyzer);
//		info.setStatus(phase, status);
//		notifyChanged();
//	}

	private void notifyChanged() {
		if (listener != null) {
			listener.stateChanged(null);
		}
	}

	public void setAnalyzerEnablement(Analyzer analyzer, boolean b) {
		AnalyzerInfo info = analyzerMap.get(analyzer);
		info.setEnabled(b);
		notifyChanged();
	}

	public void setChangeListener(ChangeListener listener) {
		this.listener = listener;
	}

	public List<Analyzer> getAnalyzers(AnalysisPhase phase) {
		if (phase == null) {
			return getAnalyzers();
		}
		List<Analyzer> list = new ArrayList<Analyzer>();
		for (AnalyzerInfo info : analyzerInfoList) {
			if (info.getNextEnabledPhaseAtOrAfter(phase) == phase) {
				list.add(info.getAnalyzer());
			}
		}
		return list;
	}

	public void setAnalyzerStartPhase(Analyzer analyzer, AnalysisPhase phase) {
		AnalyzerInfo info = analyzerMap.get(analyzer);
		info.setStartPhase(phase);
		notifyChanged();

	}

	public AnalysisPhase getAnalyzerStartPhase(Analyzer analyzer) {
		AnalyzerInfo info = analyzerMap.get(analyzer);
		return info.getAnalyzerStartPhase();
	}

	public void addScriptAnalyzer(ResourceFile file, AnalyzerType analyzerType, int priority) {
		Analyzer analyzer = new GhidraScriptAnalyzerAdapter(file, analyzerType, priority);
		AnalyzerInfo info = new AnalyzerInfo(this, analyzer, true);
		info.setStartPhase(getFirstPhase());
		analyzerMap.put(analyzer, info);
		analyzerInfoList.add(info);
		Collections.sort(analyzerInfoList);
		notifyChanged();
	}

	public void deleteScriptAnalyzer(Analyzer analyzer) {
		AnalyzerInfo removedInfo = analyzerMap.remove(analyzer);
		if (removedInfo != null) {
			analyzerInfoList.remove(removedInfo);
		}
		notifyChanged();
	}

}
