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
package ghidra.feature.vt.api;

import java.util.*;
import java.util.Map.Entry;

import org.junit.*;

import ghidra.feature.vt.api.correlator.program.ExactMatchBytesProgramCorrelatorFactory;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitorAdapter;

public abstract class AbstractCorrelatorTest extends AbstractGhidraHeadedIntegrationTest {

	protected TestEnv env;
	protected Program sourceProgram;
	protected Program destinationProgram;
	protected ArrayList<String> errors;

	public AbstractCorrelatorTest() {
		super();
	}

	protected abstract Program getSourceProgram();

	protected abstract Program getDestinationProgram();

	protected void error(VTProgramCorrelatorFactory factory, String msg) {
		errors.add(factory == null ? "" : factory.getName() + ": " + msg);
	}

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
		sourceProgram = getSourceProgram();
		destinationProgram = getDestinationProgram();
		errors = new ArrayList<>();
	}

	@After
	public void tearDown() throws Exception {
		env.release(destinationProgram);
		env.release(sourceProgram);
		env.dispose();
		sourceProgram = null;
		destinationProgram = null;
		env = null;

		if (errors.size() > 0) {
			for (String msg : errors) {
				Msg.error(this, msg);
			}
			Assert.fail("Failed to find expected matches; please see log output for details");
		}
	}

	protected void exerciseFunctionsForFactory(final VTProgramCorrelatorFactory factory,
			AddressSetView sourceSetThatShouldBeFound) throws Exception {
		String name = factory.getName();
		VTSession session =
			VTSessionDB.createVTSession(name, sourceProgram, destinationProgram, this);

		try {
			int sessionTransaction = session.startTransaction(name);
			try {
				PluginTool serviceProvider = env.getTool();
				VTAssociationManager manager = session.getAssociationManager();

				AddressSetView sourceAddressSet =
					sourceProgram.getMemory().getLoadedAndInitializedAddressSet();
				AddressSetView destinationAddressSet =
					destinationProgram.getMemory().getLoadedAndInitializedAddressSet();

				VTOptions options;
				VTProgramCorrelator correlator;
				options = factory.createDefaultOptions();
				correlator = factory.createCorrelator(serviceProvider, sourceProgram,
					sourceAddressSet, destinationProgram, destinationAddressSet, options);
				correlator.correlate(session, TaskMonitorAdapter.DUMMY_MONITOR);

				FunctionManager functionManager = sourceProgram.getFunctionManager();
				FunctionIterator functions =
					functionManager.getFunctions(sourceSetThatShouldBeFound, true);
				for (Function function : functions) {
					if (function.getBody().getNumAddresses() > ExactMatchBytesProgramCorrelatorFactory.FUNCTION_MINIMUM_SIZE_DEFAULT) {
						Address sourceEntryPoint = function.getEntryPoint();
						Collection<VTAssociation> associations =
							manager.getRelatedAssociationsBySourceAddress(sourceEntryPoint);
						if (associations.size() == 0) {
							error(factory, "no source matches for function " + function.getName() +
								" at " + sourceEntryPoint);
						}
						else {
							boolean found = false;
							Iterator<VTAssociation> iterator = associations.iterator();
							while (!found && iterator.hasNext()) {
								VTAssociation association = iterator.next();
								if (association.getDestinationAddress().equals(sourceEntryPoint)) {
									found = true;
								}
							}
							if (!found) {
								error(factory,
									"source at " + sourceEntryPoint + " didn't have a match for " +
										function.getName() + " at " + sourceEntryPoint);
							}
						}
					}
				}
			}
			finally {
				session.endTransaction(sessionTransaction, false);
			}
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected exception", e);
		}
		finally {
			session.release(this);
		}
	}

	protected void exercisePreciseMatchesForFactory(VTProgramCorrelatorFactory factory,
			Map<Address, Address> map) throws Exception {
		String name = factory.getName();
		VTSession session =
			VTSessionDB.createVTSession(name, sourceProgram, destinationProgram, this);

		try {
			int sessionTransaction = session.startTransaction(name);
			try {
				PluginTool serviceProvider = env.getTool();
				VTAssociationManager manager = session.getAssociationManager();

				AddressSetView sourceAddressSet =
					sourceProgram.getMemory().getLoadedAndInitializedAddressSet();
				AddressSetView destinationAddressSet =
					destinationProgram.getMemory().getLoadedAndInitializedAddressSet();

				VTOptions options;
				VTProgramCorrelator correlator;
				options = factory.createDefaultOptions();
				correlator = factory.createCorrelator(serviceProvider, sourceProgram,
					sourceAddressSet, destinationProgram, destinationAddressSet, options);
				correlator.correlate(session, TaskMonitorAdapter.DUMMY_MONITOR);

				HashMap<Address, Address> mapCopy = new HashMap<>(map);

				List<VTAssociation> associations = manager.getAssociations();
				for (VTAssociation association : associations) {
					Address sourceAddress = association.getSourceAddress();
					if (mapCopy.containsKey(sourceAddress)) {
						Address targetDestinationAddress = mapCopy.get(sourceAddress);
						Address actualDestinationAddress = association.getDestinationAddress();
						if (!targetDestinationAddress.equals(actualDestinationAddress)) {
							error(factory,
								"actual destination address incorrect (was " +
									actualDestinationAddress + ", should be " +
									targetDestinationAddress + ")");
						}
						mapCopy.remove(sourceAddress);
					}
					else {
						error(factory, "found a correlation at source address " + sourceAddress +
							" that should NOT have been found");
					}
				}
				if (mapCopy.size() > 0) {
					Set<Entry<Address, Address>> entries = mapCopy.entrySet();
					for (Entry<Address, Address> entry : entries) {
						error(factory, "did not find correlation " + entry.getKey() + " -> " +
							entry.getValue());
					}
				}
			}
			finally {
				session.endTransaction(sessionTransaction, false);
			}
		}
		finally {
			session.release(this);
		}
	}
}
