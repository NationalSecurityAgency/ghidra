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
package ghidra.framework.project.tool;

import org.junit.*;

import generic.test.AbstractGTest;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.test.*;

/**
 * The following tests are performed in this test driver for
 * the new front end:
 * (1) connect two running tools by one or more specified events
 * (2) disconnect one or more specified events between two connected tools
 */
public class ConnectToolsTest extends AbstractGhidraHeadedIntegrationTest {

	private final static String BAD_EVENT_NAME = "TEST_CONNECT_FOR_BAD_EVENT";
	private final static String DIRECTORY_NAME = AbstractGTest.getTestDirectoryPath();

	private Project project;

	@Before
	public void setUp() throws Exception {

		ProjectTestUtils.deleteProject(DIRECTORY_NAME, PROJECT_NAME);
		project = ProjectTestUtils.getProject(DIRECTORY_NAME, PROJECT_NAME);
	}

	@After
	public void tearDown() throws Exception {
		project.close();
		ProjectTestUtils.deleteProject(DIRECTORY_NAME, PROJECT_NAME);

	}

	/*
	 * Tests the following requirements:
	 * (1) connect two running tools by one or more specified events
	 * (2) disconnect one or more specified events between two connected tools
	 */
	@Test
	public void testConnectTools() throws Exception {

		PluginTool producer = new DummyTool("ProducerTool");
		PluginTool consumer = new DummyTool("ConsumerTool");

		ToolConnection tc;
		String eventName = null;
		//
		// TEST 1: connect the tools for both events specified
		//

		ToolManager tm = project.getToolManager();
		//
		// setup the tools to connect
		//
		String[] eventNames = producer.getToolEventNames();
		String[] consumedNames = consumer.getConsumedToolEventNames();
		if (eventNames.length == 0 || consumedNames.length == 0 ||
			(eventName = canConnectTools(eventNames, consumedNames)) == null) {
			Assert.fail("Connect Tools Failed: no event names for connection");
		}

		//
		// connect the tools with good event name
		//
		tc = tm.getConnection(producer, consumer);
		tc.connect(eventName);
		if (!tc.isConnected(eventName)) {
			Assert.fail("Connect Tools Failed: " + producer.getName() + " and " +
				consumer.getName() + " failed to CONNECT for event: " + eventName);
		}

		//
		// connect the tools with a bad event name to make sure they don't connect
		//
		try {
			tc.connect(BAD_EVENT_NAME);
		}
		catch (IllegalArgumentException e) {
			// don't do anything since we expect to get an exception here
		}
		if (tc.isConnected(BAD_EVENT_NAME)) {
			Assert.fail("Connect Tools Failed: " + producer.getName() + " and " +
				consumer.getName() + " conncted for BAD EVENT");
		}

		//
		// TEST 2: now disconnect the tools for a goodEventName, since the framework doesn't
		// do anything for disconnecting tools for events they are not connected by
		//
		tc.disconnect(eventName);
		// verify the tools are now disconnected
		if (tc.isConnected(eventName)) {
			Assert.fail("Connect Tools Failed: " + producer.getName() + " and " +
				consumer.getName() + " failed to DISCONNECT for event: " + eventName);
		}
	}

	private String canConnectTools(String[] eventNames, String[] consumedNames) {
		for (String eventName : eventNames) {
			for (String consumedName : consumedNames) {
				if (eventName.equals(consumedName)) {
					return eventName;
				}
			}
		}
		return null;
	}

}
