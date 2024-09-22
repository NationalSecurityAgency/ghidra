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
package ghidra.feature.vt.gui.plugin;

import java.util.*;

import org.jdom.Element;

import generic.cache.FixedSizeMRUCachingFactory;
import generic.stl.Pair;
import ghidra.feature.vt.api.correlator.address.*;
import ghidra.features.codecompare.correlator.CodeCompareAddressCorrelator;
import ghidra.framework.options.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.util.*;
import ghidra.util.classfinder.ClassSearcher;

public class AddressCorrelatorManager {
	private static final String ADDRESS_CORRELATORS_ELEMENT_NAME = "ADDRESS_CORRELATORS";
	private static final String ADDRESS_CORRELATOR_SUB_ELEMENT_NAME = "CORRELATOR";
	private static final String ADDRESS_CORRELATOR_NAME_KEY = "NAME";
	private static final String ADDRESS_CORRELATOR_OPTIONS_SUB_ELEMENT = "OPTIONS";

	private static final int DATA_CORRELATION_CACHE_SIZE = 5;
	private static final int FUNCTION_CORRELATION_CACHE_SIZE = 5;
	private static final Comparator<? super AddressCorrelator> CORRELATOR_COMPARATOR = (c1, c2) -> {

		int p1 = c1.getPriority();
		int p2 = c2.getPriority();
		int d = p1 - p2;
		if (d != 0) {
			return d;
		}

		// pick something as a tie-breaker
		String n1 = c1.getClass().getSimpleName();
		String n2 = c2.getClass().getSimpleName();
		return n1.compareTo(n2);
	};

	private List<AddressCorrelator> correlatorList;

	private FixedSizeMRUCachingFactory<Pair<Function, Function>, AddressCorrelation> functionCache =
		new FixedSizeMRUCachingFactory<Pair<Function, Function>, AddressCorrelation>(
			key -> getFunctionCorrelator(key.first, key.second), FUNCTION_CORRELATION_CACHE_SIZE);

	private FixedSizeMRUCachingFactory<Pair<Data, Data>, AddressCorrelation> dataCache =
		new FixedSizeMRUCachingFactory<Pair<Data, Data>, AddressCorrelation>(
			key -> getDataCorrelator(key.first, key.second), DATA_CORRELATION_CACHE_SIZE);

	public AddressCorrelatorManager(VTSessionSupplier sessionSupplier) {
		correlatorList = new ArrayList<AddressCorrelator>();
		initializeAddressCorrelators(sessionSupplier);
	}

	private void initializeAddressCorrelators(VTSessionSupplier sessionSupplier) {
		correlatorList.add(new ExactMatchAddressCorrelator(sessionSupplier));
		correlatorList.add(new VTHashedFunctionAddressCorrelator());
		correlatorList.add(new CodeCompareAddressCorrelator());

		// Note: at the time of writing this comment, the linear address correlator will not be
		// executed for functions.  The VTHashedFunctionAddressCorrelator handles function 
		// correlation between programs with the same architecture and the 
		// CodeCompareAddressCorrelator handles function correlation between programs with different
		// architectures.  This will still get called for data correlation.
		correlatorList.add(new LinearAddressCorrelator());

		correlatorList.addAll(initializeAddressCorrelators());

		correlatorList.sort(CORRELATOR_COMPARATOR);
	}

	private List<AddressCorrelator> initializeAddressCorrelators() {

		List<DiscoverableAddressCorrelator> instances =
			ClassSearcher.getInstances(DiscoverableAddressCorrelator.class);
		return new ArrayList<AddressCorrelator>(instances);
	}

	public AddressCorrelation getCorrelator(Function source, Function destination) {
		return functionCache.get(new Pair<Function, Function>(source, destination));
	}

	public AddressCorrelation getCorrelator(Data source, Data destination) {
		return dataCache.get(new Pair<Data, Data>(source, destination));
	}

	private AddressCorrelation getFunctionCorrelator(Function source, Function destination) {
		for (AddressCorrelator correlator : correlatorList) {
			AddressCorrelation correlation = correlator.correlate(source, destination);
			if (correlation != null) {
				return correlation;
			}
		}
		return null;
	}

	private AddressCorrelation getDataCorrelator(Data source, Data destination) {

		for (AddressCorrelator correlator : correlatorList) {
			AddressCorrelation correlation = correlator.correlate(source, destination);
			if (correlation != null) {
				return correlation;
			}
		}

		return null;
	}

	@SuppressWarnings("unchecked")
	// we know what the type is correct
	public void readConfigState(SaveState saveState) {
		Element correlatorsRootElement = saveState.getXmlElement(ADDRESS_CORRELATORS_ELEMENT_NAME);
		if (correlatorsRootElement == null) {
			return; // nothing saved yet
		}

		List<Element> correlatorElements =
			correlatorsRootElement.getChildren(ADDRESS_CORRELATOR_SUB_ELEMENT_NAME);
		for (Element correlatorElement : correlatorElements) {
			String className = correlatorElement.getAttributeValue(ADDRESS_CORRELATOR_NAME_KEY);
			List<Element> optionsList =
				correlatorElement.getChildren(ADDRESS_CORRELATOR_OPTIONS_SUB_ELEMENT);
			Element optionsElement = optionsList.get(0);
			List<Element> optionsContentList =
				optionsElement.getChildren(ToolOptions.XML_ELEMENT_NAME);
			Element optionsContent = optionsContentList.get(0);
			Options options = new ToolOptions(optionsContent);
			updateCorrelatorOptions(className, options);
		}
	}

	private void updateCorrelatorOptions(String className, Options newOptions) {
		for (AddressCorrelator correlator : correlatorList) {
			if (correlator.getClass().getName().equals(className)) {
				ToolOptions options = correlator.getOptions();
				options.copyOptions(newOptions);
				correlator.setOptions(options);
			}
		}
	}

	public void writeConfigState(SaveState saveState) {
		Element correlatorsRootElement = new Element(ADDRESS_CORRELATORS_ELEMENT_NAME);

		for (AddressCorrelator correlator : correlatorList) {
			Element correlatorSubElement = new Element(ADDRESS_CORRELATOR_SUB_ELEMENT_NAME);
			correlatorSubElement.setAttribute(ADDRESS_CORRELATOR_NAME_KEY,
				correlator.getClass().getName());

			ToolOptions options = correlator.getOptions();
			Element optionsSubElement = new Element(ADDRESS_CORRELATOR_OPTIONS_SUB_ELEMENT);
			Element optionsXMLContent = options.getXmlRoot(true);
			optionsSubElement.addContent(optionsXMLContent);
			correlatorSubElement.addContent(optionsSubElement);
			correlatorsRootElement.addContent(correlatorSubElement);
		}

		saveState.putXmlElement(ADDRESS_CORRELATORS_ELEMENT_NAME, correlatorsRootElement);

	}

	public Options getOptions(Class<?> class1) {
		for (AddressCorrelator correlator : correlatorList) {
			if (class1.isAssignableFrom(correlator.getClass())) {
				return correlator.getOptions();
			}
		}
		return null;
	}

	public void setOptions(Class<?> class1, Options options) {
		updateCorrelatorOptions(class1.getName(), options);
	}
}
