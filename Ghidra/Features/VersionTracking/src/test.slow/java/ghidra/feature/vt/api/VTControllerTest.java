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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import ghidra.feature.vt.api.correlator.address.LastResortAddressCorrelator;
import ghidra.feature.vt.gui.plugin.*;
import ghidra.framework.options.Options;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

import org.junit.*;

public class VTControllerTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private VTController controller;

	public VTControllerTest() {
		super();
	}

    @Before
    public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();

		tool.addPlugin(VTPlugin.class.getName());
		VTPlugin plugin = getPlugin(tool, VTPlugin.class);
		controller = new VTControllerImpl(plugin);
	}

    @After
    public void tearDown() throws Exception {
		
		env.dispose();
	}

@Test
    public void testPersistingControllerConfigState() throws Exception {

		// get out the correlator options
		AddressCorrelatorManager correlator = controller.getCorrelator();
		assertNotNull("The controller did not find any correlators", correlator);

		// set some options settings
		Options options = correlator.getOptions(LastResortAddressCorrelator.class);
		String testDefaultValue = "Test Default Value";
		String testOptionKey = "Test Option Name";
		String value = options.getString(testOptionKey, testDefaultValue);
		assertEquals(value, testDefaultValue);

		String firstNewOptionValue = "New Option Value";
		options.setString(testOptionKey, firstNewOptionValue);
		assertEquals(firstNewOptionValue, options.getString(testOptionKey, null));
		correlator.setOptions(LastResortAddressCorrelator.class, options);
		// save the options 
		SaveState saveState = new SaveState();
		controller.writeConfigState(saveState);

		// change the options
		String secondNewValue = "Second New Value";
		options.setString(testOptionKey, secondNewValue);
		correlator.setOptions(LastResortAddressCorrelator.class, options);

		// pull the values again and make sure they are still correct (that writing the config
		// state did not change the cached controller and options) 
		correlator = controller.getCorrelator();
		options = correlator.getOptions(LastResortAddressCorrelator.class);
		assertEquals(secondNewValue, options.getString(testOptionKey, null));

		// restore the options
		controller.readConfigState(saveState);

		// verify the settings
		// (we have to pull the correlator and options again, as changing the config state may 
		// change the cached values in the controller)
		correlator = controller.getCorrelator();
		options = correlator.getOptions(LastResortAddressCorrelator.class);
		assertEquals(firstNewOptionValue, options.getString(testOptionKey, null));
	}
}
