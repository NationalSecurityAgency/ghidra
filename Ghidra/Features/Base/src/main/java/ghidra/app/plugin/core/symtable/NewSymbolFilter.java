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
package ghidra.app.plugin.core.symtable;

import java.util.*;

import org.jdom.Element;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;

public class NewSymbolFilter implements SymbolFilter {

	private static final String XML_NAME = "SYMBOL_TABLE_FILTER";

	private Filter defaultLabelSourceFilter;
	private Filter defaultFunctionSourceFilter;
	private Filter aiSourceFilter;
	private Filter analysisSourceFilter;
	private Filter importedSourceFilter;
	private Filter userDefinedSourceFilter;

	private Filter[] labelFilters;
	private Filter[] nonLabelFilters;
	private Filter[] advancedFilters;

	private Filter[] activeOriginFilters = new Filter[0];
	private Filter[] activeTypeFilters = new Filter[0];
	private AdvancedFilter[] activeAdvancedFilters = new AdvancedFilter[0];

	private Map<String, Filter> filterMap = new HashMap<>();

	private boolean acceptsAllLabels;

	private boolean acceptsAll;
	private boolean acceptsAllTypes;
	private boolean acceptsAllSources;

	public NewSymbolFilter() {
		this(null);
	}

	public NewSymbolFilter(SymbolFilter oldFilter) {
		createFilters();

		for (Filter labelFilter : labelFilters) {
			filterMap.put(labelFilter.getName(), labelFilter);
		}
		for (Filter nonLabelFilter : nonLabelFilters) {
			filterMap.put(nonLabelFilter.getName(), nonLabelFilter);
		}
		for (Filter advancedFilter : advancedFilters) {
			filterMap.put(advancedFilter.getName(), advancedFilter);
		}
		filterMap.put(defaultLabelSourceFilter.getName(), defaultLabelSourceFilter);
		filterMap.put(defaultFunctionSourceFilter.getName(), defaultFunctionSourceFilter);
		filterMap.put(aiSourceFilter.getName(), aiSourceFilter);
		filterMap.put(analysisSourceFilter.getName(), analysisSourceFilter);
		filterMap.put(importedSourceFilter.getName(), importedSourceFilter);
		filterMap.put(userDefinedSourceFilter.getName(), userDefinedSourceFilter);

		if (oldFilter instanceof NewSymbolFilter) {
			NewSymbolFilter filter = (NewSymbolFilter) oldFilter;
			defaultLabelSourceFilter.setActive(filter.defaultLabelSourceFilter.isActive());
			defaultFunctionSourceFilter.setActive(filter.defaultFunctionSourceFilter.isActive());
			aiSourceFilter.setActive(filter.aiSourceFilter.isActive());
			analysisSourceFilter.setActive(filter.analysisSourceFilter.isActive());
			importedSourceFilter.setActive(filter.importedSourceFilter.isActive());
			userDefinedSourceFilter.setActive(filter.userDefinedSourceFilter.isActive());

			for (int i = 0; i < labelFilters.length; i++) {
				labelFilters[i].setActive(filter.labelFilters[i].isActive());
			}
			for (int i = 0; i < nonLabelFilters.length; i++) {
				nonLabelFilters[i].setActive(filter.nonLabelFilters[i].isActive());
			}
			for (int i = 0; i < advancedFilters.length; i++) {
				advancedFilters[i].setActive(filter.advancedFilters[i].isActive());
			}
			rebuildActiveFilters();
		}
		else {
			setFilterDefaults();
		}
	}

	@Override
	public boolean accepts(Symbol symbol, Program program) {
		if (acceptsAll) {
			return true;
		}
		if (!isAcceptableOrigin(program, symbol)) {
			return false;
		}
		if (!isAcceptableType(program, symbol)) {
			return false;
		}
		if (!passesAdvancedFilters(program, symbol)) {
			return false;
		}
		return true;
	}

	private boolean isAcceptableOrigin(Program program, Symbol symbol) {
		if (acceptsAllSources) {
			return true;
		}
		for (Filter activeOriginFilter : activeOriginFilters) {
			if (activeOriginFilter.matches(program, symbol)) {
				return true;
			}
		}
		return false;
	}

	private boolean isAcceptableType(Program program, Symbol symbol) {
		if (acceptsAllTypes) {
			return true;
		}
		for (Filter activeTypeFilter : activeTypeFilters) {
			if (activeTypeFilter.matches(program, symbol)) {
				return true;
			}
		}
		return false;
	}

	private boolean passesAdvancedFilters(Program program, Symbol symbol) {
		boolean applicable = false;
		for (AdvancedFilter activeAdvancedFilter : activeAdvancedFilters) {
			if (activeAdvancedFilter.isApplicable(symbol)) {
				applicable = true;
				if (activeAdvancedFilter.matches(program, symbol)) {
					return true;
				}
			}
		}
		if (!applicable) { // if none of the filters were applicable, then the symbol passes.
			return true;
		}
		return false;
	}

	@Override
	public boolean acceptsOnlyCodeSymbols() {
		for (Filter activeTypeFilter : activeTypeFilters) {
			if (!activeTypeFilter.onlyCodeSymbols) {
				return false;
			}
		}
		return true;
	}

	@Override
	public boolean acceptsDefaultLabelSymbols() {
		if (!defaultLabelSourceFilter.isActive()) {
			return false;
		}
		for (Filter activeTypeFilter : activeTypeFilters) {
			if (activeTypeFilter.includesDefaults) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean acceptsAll() {
		return acceptsAll;
	}

	String[] getSourceFilterNames() {
		return new String[] { defaultLabelSourceFilter.getName(),
			defaultFunctionSourceFilter.getName(), aiSourceFilter.getName(),
			analysisSourceFilter.getName(), userDefinedSourceFilter.getName(),
			importedSourceFilter.getName() };
	}

	String[] getLabelTypeFilterNames() {
		String[] names = new String[labelFilters.length];
		for (int i = 0; i < names.length; i++) {
			names[i] = labelFilters[i].getName();
		}
		return names;
	}

	String[] getNonLabelTypeFilterNames() {
		String[] names = new String[nonLabelFilters.length];
		for (int i = 0; i < names.length; i++) {
			names[i] = nonLabelFilters[i].getName();
		}
		return names;
	}

	String[] getAdvancedFilterNames() {
		String[] names = new String[advancedFilters.length];
		for (int i = 0; i < names.length; i++) {
			names[i] = advancedFilters[i].getName();
		}
		return names;
	}

	void setFilter(String filterName, boolean active) {
		Filter filter = filterMap.get(filterName);
		if (filter != null) {
			filter.setActive(active);
			rebuildActiveFilters();
		}
		else {
			Msg.error(this, "filter " + filterName + " not found");
		}
	}

	String getFilterDescription(String filterName) {
		Filter filter = filterMap.get(filterName);
		return filter != null ? filter.getDescription() : "";
	}

	boolean isActive(String filterName) {
		Filter filter = filterMap.get(filterName);
		return filter != null && filter.active;
	}

	boolean isEnabled(String filterName) {
		Filter filter = filterMap.get(filterName);
		return filter != null && filter.isEnabled();
	}

	public int getActiveSourceFilterCount() {
		return activeOriginFilters.length;
	}

	public int getActiveTypeFilterCount() {
		return activeTypeFilters.length;
	}

	public int getActiveAdvancedFilterCount() {
		return activeAdvancedFilters.length;
	}

	Element saveToXml() {
		Element root = new Element(XML_NAME);
		filterMap.values().forEach(filter -> {
			Element filterElement = filter.saveToXml();
			root.addContent(filterElement);
		});
		return root;
	}

	void restoreFromXml(Element element) {

		@SuppressWarnings("unchecked")
		List<Element> children = element.getChildren();
		for (Element child : children) {
			String childName = child.getAttributeValue(Filter.NAME_ATTRIBUTE);
			Filter f = filterMap.get(childName);
			if (f != null) { // NOTE: filter definition may have been dropped and not found
				f.restoreFromXml(child);
			}
		}

		rebuildActiveFilters();
	}

	void setFilterDefaults() {
		for (Filter labelFilter : labelFilters) {
			labelFilter.setActive(true);
		}
		for (Filter nonLabelFilter : nonLabelFilters) {
			nonLabelFilter.setActive(false);
		}
		for (Filter advancedFilter : advancedFilters) {
			advancedFilter.setActive(false);
		}
		defaultFunctionSourceFilter.setActive(true);
		defaultLabelSourceFilter.setActive(false);
		aiSourceFilter.setActive(true);
		analysisSourceFilter.setActive(true);
		importedSourceFilter.setActive(true);
		userDefinedSourceFilter.setActive(true);

		rebuildActiveFilters();
	}

	private void rebuildActiveFilters() {
		ArrayList<Filter> originList = new ArrayList<>(3);

		if (defaultLabelSourceFilter.isActive()) {
			originList.add(defaultLabelSourceFilter);
		}
		if (defaultFunctionSourceFilter.isActive()) {
			originList.add(defaultFunctionSourceFilter);
		}
		if (aiSourceFilter.isActive()) {
			originList.add(aiSourceFilter);
		}
		if (analysisSourceFilter.isActive()) {
			originList.add(analysisSourceFilter);
		}
		if (importedSourceFilter.isActive()) {
			originList.add(importedSourceFilter);
		}
		if (userDefinedSourceFilter.isActive()) {
			originList.add(userDefinedSourceFilter);
		}

		activeOriginFilters = new Filter[originList.size()];
		originList.toArray(activeOriginFilters);

		ArrayList<Filter> typeList = new ArrayList<>(labelFilters.length);
		acceptsAllLabels = true;
		for (Filter labelFilter : labelFilters) {
			if (labelFilter.isActive()) {
				typeList.add(labelFilter);
			}
			else {
				acceptsAllLabels = false;
			}
		}
		for (Filter nonLabelFilter : nonLabelFilters) {
			if (nonLabelFilter.isActive()) {
				typeList.add(nonLabelFilter);
			}
		}
		activeTypeFilters = new Filter[typeList.size()];
		typeList.toArray(activeTypeFilters);

		ArrayList<Filter> advancedList = new ArrayList<>(advancedFilters.length);
		for (Filter advancedFilter : advancedFilters) {
			if (advancedFilter.isActive() && advancedFilter.isEnabled()) {
				advancedList.add(advancedFilter);
			}
		}
		activeAdvancedFilters = new AdvancedFilter[advancedList.size()];
		advancedList.toArray(activeAdvancedFilters);

		acceptsAllTypes = activeTypeFilters.length == labelFilters.length + nonLabelFilters.length;
		acceptsAllSources =
			defaultLabelSourceFilter.isActive() && defaultFunctionSourceFilter.isActive() &&
				importedSourceFilter.isActive() && aiSourceFilter.isActive() &&
				analysisSourceFilter.isActive() && userDefinedSourceFilter.isActive();
		acceptsAll = acceptsAllTypes && acceptsAllSources && activeAdvancedFilters.length == 0;

	}

	private void createFilters() {
		defaultLabelSourceFilter = new Filter("Default (Labels)", true, false) {
			@Override
			boolean matches(Program program, Symbol symbol) {
				return symbol.getSymbolType() != SymbolType.FUNCTION &&
					symbol.getSource() == SourceType.DEFAULT;
			}

			@Override
			String getDescription() {
				return "Include Symbols that have default names.";
			}

		};
		defaultFunctionSourceFilter = new Filter("Default (Functions)", true, false) {
			@Override
			boolean matches(Program program, Symbol symbol) {
				return symbol.getSymbolType() == SymbolType.FUNCTION &&
					symbol.getSource() == SourceType.DEFAULT;
			}

			@Override
			String getDescription() {
				return "Include Symbols that have default names.";
			}
		};
		aiSourceFilter = new Filter(SourceType.AI.getDisplayString(), false, false) {
			@Override
			boolean matches(Program program, Symbol symbol) {
				return symbol.getSource() == SourceType.AI;
			}

			@Override
			String getDescription() {
				return "Include Symbols named by auto-analysis.";
			}
		};
		analysisSourceFilter = new Filter(SourceType.ANALYSIS.getDisplayString(), false, false) {
			@Override
			boolean matches(Program program, Symbol symbol) {
				return symbol.getSource() == SourceType.ANALYSIS;
			}

			@Override
			String getDescription() {
				return "Include Symbols named by auto-analysis.";
			}
		};
		importedSourceFilter = new Filter(SourceType.IMPORTED.getDisplayString(), false, false) {
			@Override
			boolean matches(Program program, Symbol symbol) {
				return symbol.getSource() == SourceType.IMPORTED;
			}

			@Override
			String getDescription() {
				return "Include Symbols imported from external information.";
			}
		};
		userDefinedSourceFilter =
			new Filter(SourceType.USER_DEFINED.getDisplayString(), false, false) {
				@Override
				boolean matches(Program program, Symbol symbol) {
					return symbol.getSource() == SourceType.USER_DEFINED;
				}

				@Override
				String getDescription() {
					return "Include Symbols named by the user.";
				}
			};

		Filter instructionFilter = new Filter("Instruction Labels", true, true) {
			@Override
			boolean matches(Program program, Symbol symbol) {
				if (symbol.getSymbolType() == SymbolType.LABEL && !symbol.isExternal()) {
					if (acceptsAllLabels) {
						return true;
					}
					Listing l = program.getListing();
					Address addr = symbol.getAddress();
					CodeUnit cu = l.getCodeUnitContaining(addr);
					if (cu == null) {
						return true;
					}
					if (cu instanceof Instruction) {	// only include if no function 
						return program.getFunctionManager().getFunctionAt(addr) == null;
					}
				}
				return false;
			}

			@Override
			String getDescription() {
				return "Include labels on instructions.";
			}
		};

		Filter dataFilter = new Filter("Data Labels", true, true) {
			@Override
			boolean matches(Program program, Symbol symbol) {
				if (symbol.getSymbolType() == SymbolType.LABEL) {
					if (acceptsAllLabels || symbol.isExternal()) {
						return true;
					}
					Listing l = program.getListing();
					Address addr = symbol.getAddress();
					CodeUnit cu = l.getCodeUnitContaining(addr);
					if (cu == null) {
						return true;
					}
					if (cu instanceof Data) {
						return program.getFunctionManager().getFunctionAt(addr) == null;
					}
				}
				return false;
			}

			@Override
			String getDescription() {
				return "Include labels on Data.";
			}

		};

		Filter functionFilter = new Filter("Function Labels", false, true) {
			@Override
			boolean matches(Program program, Symbol symbol) {
				if (symbol.getSymbolType() == SymbolType.LABEL && !symbol.isExternal()) {
					if (acceptsAllLabels) {
						return true;
					}
					return program.getFunctionManager().getFunctionAt(symbol.getAddress()) != null;
				}
				return (symbol.getSymbolType() == SymbolType.FUNCTION);
			}

			@Override
			String getDescription() {
				return "Include Labels at function entry points";
			}
		};

		Filter parameterFilter = new Filter("Parameters", false, false) {
			@Override
			boolean matches(Program program, Symbol symbol) {
				return (symbol.getSymbolType() == SymbolType.PARAMETER);
			}

			@Override
			String getDescription() {
				return "Include Symbols that are function parameters";
			}
		};
		Filter localVarsFilter = new Filter("Local Variables", false, false) {
			@Override
			boolean matches(Program program, Symbol symbol) {
				return (symbol.getSymbolType() == SymbolType.LOCAL_VAR);
			}

			@Override
			String getDescription() {
				return "Include Symbols that are function local variables.";
			}
		};
		Filter externalLibraryFilter = new Filter("External Library", false, false) {
			@Override
			boolean matches(Program program, Symbol symbol) {
				return symbol.getSymbolType() == SymbolType.LIBRARY;
			}

			@Override
			String getDescription() {
				return "Include Symbols that are External library names (e.g. Use32.dll).";
			}

		};
		Filter namespaceFilter = new Filter("Namespaces", false, false) {
			@Override
			boolean matches(Program program, Symbol symbol) {
				return symbol.getSymbolType() == SymbolType.NAMESPACE;
			}

			@Override
			String getDescription() {
				return "Include Symbols that are namespaces.";
			}

		};
		Filter classFilter = new Filter("Classes", false, false) {
			@Override
			boolean matches(Program program, Symbol symbol) {
				return symbol.getSymbolType() == SymbolType.CLASS;
			}

			@Override
			String getDescription() {
				return "Include Symbols that are C++ classes";
			}

		};
		Filter globalRegisterFilter = new Filter("Global Register Variables", false, false) {
			@Override
			boolean matches(Program program, Symbol symbol) {
				return symbol.getSymbolType() == SymbolType.GLOBAL_VAR;
			}

			@Override
			String getDescription() {
				return "Include Symbols that are global register variables";
			}

		};

		AdvancedFilter registerFilter = new AdvancedFilter("Register Variables") {
			@Override
			boolean matches(Program program, Symbol symbol) {
				SymbolType type = symbol.getSymbolType();
				if (type == SymbolType.LOCAL_VAR || type == SymbolType.PARAMETER) {
					Variable var = (Variable) symbol.getObject();
					return var.isRegisterVariable() || var.isCompoundVariable();
				}
				return false;
			}

			@Override
			boolean isApplicable(Symbol symbol) {
				SymbolType type = symbol.getSymbolType();
				return type == SymbolType.PARAMETER || type == SymbolType.LOCAL_VAR;
			}

			@Override
			String getDescription() {
				return "Only include Function parameters or local variables that are register based.\n" +
					"This Filter only affects parameters or local variables.";
			}
		};
		registerFilter.addApplicableFilter(parameterFilter);
		registerFilter.addApplicableFilter(localVarsFilter);

		AdvancedFilter stackFilter = new AdvancedFilter("Stack Variables") {
			@Override
			boolean matches(Program program, Symbol symbol) {
				SymbolType type = symbol.getSymbolType();
				if (type == SymbolType.LOCAL_VAR || type == SymbolType.PARAMETER) {
					Variable var = (Variable) symbol.getObject();
					return var.isStackVariable();
				}
				return false;
			}

			@Override
			boolean isApplicable(Symbol symbol) {
				SymbolType type = symbol.getSymbolType();
				return type == SymbolType.PARAMETER || type == SymbolType.LOCAL_VAR;
			}

			@Override
			String getDescription() {
				return "Only include Function parameters or local variables that are stack based.\n" +
					"This Filter only affects parameter or local variable symbols.";
			}
		};
		stackFilter.addApplicableFilter(parameterFilter);
		stackFilter.addApplicableFilter(localVarsFilter);

		AdvancedFilter externalFilter = new AdvancedFilter("Externals") {
			@Override
			boolean matches(Program program, Symbol symbol) {
				return symbol.isExternal();
			}

			@Override
			boolean isApplicable(Symbol symbol) {
				SymbolType type = symbol.getSymbolType();
				return type == SymbolType.LABEL || type == SymbolType.CLASS ||
					type == SymbolType.FUNCTION || type == SymbolType.NAMESPACE ||
					type == SymbolType.PARAMETER || type == SymbolType.LOCAL_VAR;
			}

			@Override
			String getDescription() {
				return "Only include symbols that are external";
			}

		};
		externalFilter.addApplicableFilter(dataFilter);
		externalFilter.addApplicableFilter(instructionFilter);
		externalFilter.addApplicableFilter(classFilter);
		externalFilter.addApplicableFilter(functionFilter);
		externalFilter.addApplicableFilter(localVarsFilter);
		externalFilter.addApplicableFilter(parameterFilter);
		externalFilter.addApplicableFilter(namespaceFilter);

		AdvancedFilter nonExternalFilter = new AdvancedFilter("Non-Externals") {
			@Override
			boolean matches(Program program, Symbol symbol) {
				return !symbol.isExternal();
			}

			@Override
			boolean isApplicable(Symbol symbol) {
				SymbolType type = symbol.getSymbolType();
				return type == SymbolType.LABEL || type == SymbolType.CLASS ||
					type == SymbolType.FUNCTION || type == SymbolType.NAMESPACE ||
					type == SymbolType.PARAMETER || type == SymbolType.LOCAL_VAR;
			}

			@Override
			String getDescription() {
				return "Only include symbols that are not external";
			}

		};
		nonExternalFilter.addApplicableFilter(dataFilter);
		nonExternalFilter.addApplicableFilter(instructionFilter);
		nonExternalFilter.addApplicableFilter(classFilter);
		nonExternalFilter.addApplicableFilter(functionFilter);
		nonExternalFilter.addApplicableFilter(localVarsFilter);
		nonExternalFilter.addApplicableFilter(parameterFilter);
		nonExternalFilter.addApplicableFilter(namespaceFilter);

		AdvancedFilter globalFilter = new AdvancedFilter("Globals") {
			@Override
			boolean matches(Program program, Symbol symbol) {
				return symbol.isGlobal();
			}

			@Override
			boolean isApplicable(Symbol symbol) {
				SymbolType type = symbol.getSymbolType();
				return type == SymbolType.LABEL || type == SymbolType.CLASS ||
					type == SymbolType.FUNCTION || type == SymbolType.NAMESPACE;
			}

			@Override
			String getDescription() {
				return "Only include symbols that in the global namespace.\n" +
					"This Filter only affects label, function, class, and namespace symbols.";
			}

		};
		globalFilter.addApplicableFilter(dataFilter);
		globalFilter.addApplicableFilter(instructionFilter);
		globalFilter.addApplicableFilter(classFilter);
		globalFilter.addApplicableFilter(functionFilter);
		globalFilter.addApplicableFilter(namespaceFilter);

		AdvancedFilter localFilter = new AdvancedFilter("Locals") {
			@Override
			boolean matches(Program program, Symbol symbol) {
				return !symbol.isGlobal() && !symbol.isExternal();
			}

			@Override
			boolean isApplicable(Symbol symbol) {
				SymbolType type = symbol.getSymbolType();
				return type == SymbolType.LABEL || type == SymbolType.CLASS ||
					type == SymbolType.FUNCTION || type == SymbolType.NAMESPACE;
			}

			@Override
			String getDescription() {
				return "Only include symbols that in a local namespace (i.e. not the global namespace.)\n" +
					"This Filter only affects label, function, class, and namespace symbols.";
			}
		};
		localFilter.addApplicableFilter(instructionFilter);
		localFilter.addApplicableFilter(dataFilter);
		localFilter.addApplicableFilter(classFilter);
		localFilter.addApplicableFilter(functionFilter);
		localFilter.addApplicableFilter(namespaceFilter);

		AdvancedFilter notInMemoryFilter = new AdvancedFilter("Not In Memory") {
			@Override
			boolean matches(Program program, Symbol symbol) {
				Memory mem = program.getMemory();
				return !mem.contains(symbol.getAddress());
			}

			@Override
			boolean isApplicable(Symbol symbol) {
				SymbolType type = symbol.getSymbolType();
				return type == SymbolType.LABEL;
			}

			@Override
			String getDescription() {
				return "Only include labels that are at addresses not contained in memory.\n" +
					"This Filter only affects label symbols.";
			}

		};
		notInMemoryFilter.addApplicableFilter(instructionFilter);
		notInMemoryFilter.addApplicableFilter(dataFilter);

		AdvancedFilter notReferencedFilter = new AdvancedFilter("Unreferenced") {
			@Override
			boolean matches(Program program, Symbol symbol) {
				return !program.getReferenceManager().hasReferencesTo(symbol.getAddress());
			}

			@Override
			boolean isApplicable(Symbol symbol) {
				SymbolType type = symbol.getSymbolType();
				return type == SymbolType.LABEL || type == SymbolType.FUNCTION;
			}

			@Override
			String getDescription() {
				return "Only include labels or functions that have no references to them (i.e. dead code.)\n" +
					"This Filter only affects label and function symbols";
			}
		};
		notReferencedFilter.addApplicableFilter(instructionFilter);
		notReferencedFilter.addApplicableFilter(dataFilter);
		notReferencedFilter.addApplicableFilter(functionFilter);

		AdvancedFilter offcutFilter = new AdvancedFilter("Offcut Labels") {
			@Override
			boolean matches(Program program, Symbol symbol) {
				Listing l = program.getListing();
				CodeUnit cu = l.getCodeUnitContaining(symbol.getAddress());
				if (cu != null) {
					return !cu.getMinAddress().equals(symbol.getAddress());
				}
				return false;
			}

			@Override
			boolean isApplicable(Symbol symbol) {
				SymbolType type = symbol.getSymbolType();
				return type == SymbolType.LABEL || type == SymbolType.FUNCTION;
			}

			@Override
			String getDescription() {
				return "Only include labels at addresses that are offcut (i.e. inside an instruction or data item.\n" +
					"This Filter only affects label and function symbols.";
			}
		};
		offcutFilter.addApplicableFilter(instructionFilter);
		offcutFilter.addApplicableFilter(dataFilter);
		offcutFilter.addApplicableFilter(functionFilter);

		AdvancedFilter entryFilter = new AdvancedFilter("Entry Points") {
			@Override
			boolean matches(Program program, Symbol symbol) {
				return symbol.isExternalEntryPoint();
			}

			@Override
			boolean isApplicable(Symbol symbol) {
				SymbolType type = symbol.getSymbolType();
				return type == SymbolType.LABEL || type == SymbolType.FUNCTION;
			}

			@Override
			String getDescription() {
				return "Only include labels or functions that are at external entry points.\n" +
					"This Filter only affects label and function symbols";
			}
		};
		entryFilter.addApplicableFilter(instructionFilter);
		entryFilter.addApplicableFilter(dataFilter);
		entryFilter.addApplicableFilter(functionFilter);

		AdvancedFilter subroutineFilter = new AdvancedFilter("Subroutines") {
			@Override
			boolean matches(Program program, Symbol symbol) {
				Reference[] refs = symbol.getReferences(null);
				for (Reference ref : refs) {
					if (ref.getReferenceType().isCall()) {
						return true;
					}
				}
				return false;
			}

			@Override
			boolean isApplicable(Symbol symbol) {
				SymbolType type = symbol.getSymbolType();
				return type == SymbolType.LABEL;
			}

			@Override
			String getDescription() {
				return "Include labels that are \"called\" by some instruction.\n" +
					"This Filter only affects label symbols.";
			}
		};
		subroutineFilter.addApplicableFilter(instructionFilter);

		AdvancedFilter primaryFilter = new AdvancedFilter("Primary Labels") {
			@Override
			boolean matches(Program program, Symbol symbol) {
				return symbol.isPrimary();
			}

			@Override
			boolean isApplicable(Symbol symbol) {
				SymbolType type = symbol.getSymbolType();
				return type == SymbolType.LABEL || type == SymbolType.FUNCTION;
			}

			@Override
			String getDescription() {
				return "Only include labels or functions that are the primary symbol at an address";
			}
		};
		primaryFilter.addApplicableFilter(instructionFilter);
		primaryFilter.addApplicableFilter(dataFilter);
		primaryFilter.addApplicableFilter(functionFilter);

		AdvancedFilter nonPrimaryFilter = new AdvancedFilter("Non-Primary Labels") {
			@Override
			boolean matches(Program program, Symbol symbol) {
				return !symbol.isPrimary();
			}

			@Override
			boolean isApplicable(Symbol symbol) {
				SymbolType type = symbol.getSymbolType();
				return type == SymbolType.LABEL || type == SymbolType.FUNCTION;
			}

			@Override
			String getDescription() {
				return "Only include labels or functions that are not the primary symbol at an address";
			}
		};
		nonPrimaryFilter.addApplicableFilter(instructionFilter);
		nonPrimaryFilter.addApplicableFilter(dataFilter);
		nonPrimaryFilter.addApplicableFilter(functionFilter);

		labelFilters = new Filter[] { instructionFilter, dataFilter, functionFilter };
		nonLabelFilters = new Filter[] { namespaceFilter, classFilter, externalLibraryFilter,
			parameterFilter, localVarsFilter, globalRegisterFilter };
		advancedFilters = new Filter[] { externalFilter, nonExternalFilter, primaryFilter,
			nonPrimaryFilter, globalFilter, localFilter, registerFilter, stackFilter, entryFilter,
			subroutineFilter, notInMemoryFilter, notReferencedFilter, offcutFilter };

	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private abstract static class AdvancedFilter extends Filter {

		private static final String ADVANCED_ELEMENT_NAME = "ADVANCED_FILTER";

		List<Filter> applicableFilters = new ArrayList<>();

		AdvancedFilter(String name) {
			super(name, false, false);
		}

		abstract boolean isApplicable(Symbol s);

		void addApplicableFilter(Filter filter) {
			applicableFilters.add(filter);
		}

		@Override
		boolean isEnabled() {
			for (Filter filter : applicableFilters) {
				if (filter.isActive()) {
					return true;
				}
			}
			return false;
		}

		@Override
		Element saveToXml() {
			/*
			 	<ADVANCED_FILTER NAME="foo" 
			 	                
					<FILTER NAME="one" 	
							ACTIVE="false" 
							INCLUDES_DEFAULTS="true" 
							ONLY_CODE_SYMBOLS="false" />
							
					<FILTER NAME="two" 	
							ACTIVE="false" 
							INCLUDES_DEFAULTS="true" 
							ONLY_CODE_SYMBOLS="false" />
			 	                
			 	</ADVANCED_FILTER>
			 */

			Element element = new Element(ADVANCED_ELEMENT_NAME);
			element.setAttribute(NAME_ATTRIBUTE, name);
			element.setAttribute(ACTIVE_ATTRIBUTE, Boolean.toString(active));

			for (Filter subFilter : applicableFilters) {
				Element subElement = subFilter.saveToXml();
				element.addContent(subElement);
			}

			return element;
		}

		@Override
		void restoreFromXml(Element element) {
			if (!ADVANCED_ELEMENT_NAME.equals(element.getName())) {
				Msg.error(this, "Incorrect xml stored for filter: " + name);
				return;
			}

			String nameValue = element.getAttributeValue(NAME_ATTRIBUTE);
			if (nameValue == null) {
				Msg.error(this, "No name found for xml element: " + name);
				return;
			}

			this.name = nameValue;
			this.active = parseBooleanAttribute(element, ACTIVE_ATTRIBUTE);

			@SuppressWarnings("unchecked")
			List<Element> children = element.getChildren();
			for (Element child : children) {
				String childName = child.getAttributeValue(Filter.NAME_ATTRIBUTE);
				Filter childFilter = getFilter(childName);
				if (childFilter == null) {
					Msg.error(this, "Unable to locate advanced sub-filter: " + childName);
					continue; // shouldn't happen
				}

				childFilter.restoreFromXml(child);
			}

		}

		private Filter getFilter(String childName) {
			for (Filter filter : applicableFilters) {
				if (filter.getName().equals(childName)) {
					return filter;
				}
			}
			return null;
		}

	}

	private abstract static class Filter {

		protected static final String ELEMENT_NAME = "FILTER";
		protected static final String NAME_ATTRIBUTE = "NAME";
		protected static final String ACTIVE_ATTRIBUTE = "ACTIVE";
		protected static final String INCLUDES_DEFAULTS_ATTRIBUTE = "INCLUDES_DEFAULTS";
		protected static final String ONLY_CODE_SYMBOLS_ATTRIBUTE = "ONLY_CODE_SYMBOLS";

		protected String name;
		protected boolean active;
		private boolean includesDefaults;
		private boolean onlyCodeSymbols;

		Filter(String name, boolean includesDefaults, boolean onlyCodeSymbols) {
			this.name = name;
			this.includesDefaults = includesDefaults;
			this.onlyCodeSymbols = onlyCodeSymbols;
		}

		abstract boolean matches(Program program, Symbol symbol);

		abstract String getDescription();

		Element saveToXml() {
			/*
			 	<FILTER NAME="foo" ACTIVE="false" INCLUDES_DEFAULTS="true" ONLY_CODE_SYMBOLS="false" />
			 */

			Element element = new Element(ELEMENT_NAME);
			element.setAttribute(NAME_ATTRIBUTE, name);
			element.setAttribute(ACTIVE_ATTRIBUTE, Boolean.toString(active));
			element.setAttribute(INCLUDES_DEFAULTS_ATTRIBUTE, Boolean.toString(includesDefaults));
			element.setAttribute(ONLY_CODE_SYMBOLS_ATTRIBUTE, Boolean.toString(onlyCodeSymbols));
			return element;
		}

		void restoreFromXml(Element element) {
			String nameValue = element.getAttributeValue(NAME_ATTRIBUTE);
			if (nameValue == null) {
				Msg.error(this, "No name found for xml element: " + name);
				return;
			}

			this.name = nameValue;
			this.active = parseBooleanAttribute(element, ACTIVE_ATTRIBUTE);
			this.includesDefaults = parseBooleanAttribute(element, INCLUDES_DEFAULTS_ATTRIBUTE);
			this.onlyCodeSymbols = parseBooleanAttribute(element, ONLY_CODE_SYMBOLS_ATTRIBUTE);
		}

		protected boolean parseBooleanAttribute(Element element, String attributeName) {
			String value = element.getAttributeValue(attributeName, Boolean.FALSE.toString());
			return Boolean.parseBoolean(value);
		}

		boolean isEnabled() {
			return true;
		}

		String getName() {
			return name;
		}

		boolean isActive() {
			return active;
		}

		void setActive(boolean b) {
			active = b;
		}
	}

}
