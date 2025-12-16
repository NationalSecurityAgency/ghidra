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
package ghidra.framework.options;

import static org.junit.Assert.*;

import org.jdom.Element;
import org.junit.Test;

import generic.test.AbstractGTest;
import ghidra.util.xml.XmlUtilities;

public class SaveStateTest {

	@Test
	public void testEmptySaveState() throws Exception {

		SaveState ss = new SaveState("Client_Name");
		SaveState restored = saveAndRestoreToXml(ss);
		assertEquals("Client_Name", restored.getName());
	}

	@Test
	public void testEmptyNestedSaveState() throws Exception {

		SaveState ss = new SaveState();
		SaveState nestedSs = new SaveState("Client_Name2");
		ss.putSaveState("Key", nestedSs);

		SaveState restored = saveAndRestoreToXml(ss);
		SaveState restoredNestedSs = restored.getSaveState("Key");
		assertEquals("Client_Name2", restoredNestedSs.getName());
	}

	@Test
	public void testRestoreFromXml_BackwardCompatibility_OldestStyleSaveState() throws Exception {

		/*
		 	Test for backwards compatibility from the original format for save state that was
		 	around since the beginning.
		 	
		 	Note: the oldest style had:
		 		- no 'KEY' attribute
		 		- an extra layer of <SAVE_STATE> between the top layer and <STATE> element
		 */

		//@formatter:off
		String xml = """
			<SAVE_STATE>
				<SAVE_STATE NAME="Bar" TYPE="SaveState">
			        <SAVE_STATE>
			            <STATE NAME="DATED_OPTION" TYPE="int" VALUE="3" />
			        </SAVE_STATE>
			    </SAVE_STATE>
			</SAVE_STATE>
				""";
		//@formatter:on

		Element element = XmlUtilities.fromString(xml);
		SaveState rootSaveState = new SaveState(element);

		SaveState saveState = rootSaveState.getSaveState("Bar");
		assertNotNull(saveState);

		// In the old style, 'NAME' was used as the key value and the state itself had no name.
		// In this case, getName() returns the default of 'SAVE_STATE'.
		assertEquals(SaveState.SAVE_STATE_TAG_NAME, saveState.getName());

		assertEquals(3, saveState.getInt("DATED_OPTION", -1));
	}

	@Test
	public void testRestoreFromXml_BackwardCompatibility_OldestStyleSaveState_CustomXmlTagName()
			throws Exception {

		/*
		 	Test for backwards compatibility from an intermediate format for save state that was
		 	around for a few months.
		 	
		 	Note: the oldest style had:
		 		- no 'KEY' attribute
		 		- an extra layer of <SAVE_STATE> between the top layer and <STATE> element
		 		- a custom xml tag instead of <SAVE_STATE>
		 */

		//@formatter:off
		String xml = """
			<SAVE_STATE>
			    <SAVE_STATE NAME="TEST" TYPE="SaveState">
			        <BAR>
			            <STATE NAME="DATED_OPTION" TYPE="int" VALUE="3" />
			        </BAR>
			    </SAVE_STATE>
			</SAVE_STATE>
				""";
		//@formatter:on

		Element element = XmlUtilities.fromString(xml);
		SaveState rootSaveState = new SaveState(element);

		SaveState saveState = rootSaveState.getSaveState("TEST");
		assertNotNull(saveState);

		// In the old style, 'NAME' was used as the key value and the state itself had no name.
		// In this case, getName() returns the default of 'SAVE_STATE'.
		assertEquals(SaveState.SAVE_STATE_TAG_NAME, saveState.getName());
		assertEquals(3, saveState.getInt("DATED_OPTION", -1));
	}

	@Test
	public void testRestoreFromXml_BackwardCompatibility_OldestStyleSaveState_EmtpyNestdState()
			throws Exception {

		/*
		 	Test for backwards compatibility from the original format for save state that was
		 	around since the beginning.
		 	
		 	Note: the oldest style had:
		 		- no 'KEY' attribute
		 		- an extra layer of <SAVE_STATE> between the top layer and <STATE> element
		 */

		//@formatter:off
		String xml = """
			<SAVE_STATE>
				<SAVE_STATE NAME="Bar" TYPE="SaveState" />
			</SAVE_STATE>
				""";
		//@formatter:on

		Element element = XmlUtilities.fromString(xml);
		SaveState rootSaveState = new SaveState(element);

		SaveState saveState = rootSaveState.getSaveState("Bar");
		assertNotNull(saveState);

		// In the old style, 'NAME' was used as the key value and the state itself had no name.
		// In this case, getName() returns the default of 'SAVE_STATE'.
		assertEquals(SaveState.SAVE_STATE_TAG_NAME, saveState.getName());
	}

	@Test
	public void testRestoreFromXml_BackwardCompatibility_RecentStyleSaveState() throws Exception {

		/*
		 	Test for backwards compatibility from an intermediate format for save state that was
		 	around for a few months.
		 	
		 	Note: the oldest style had:
		 		- no 'KEY' attribute
		 		- NO extra layer of <SAVE_STATE> between the top layer and <STATE> element
		 */

		//@formatter:off
		String xml = """
			<SAVE_STATE>
			    <SAVE_STATE NAME="Bar" TYPE="SaveState">
			        <STATE NAME="DATED_OPTION" TYPE="int" VALUE="3" />
			    </SAVE_STATE>
			</SAVE_STATE>
				""";
		//@formatter:on

		Element element = XmlUtilities.fromString(xml);
		SaveState rootSaveState = new SaveState(element);

		SaveState saveState = rootSaveState.getSaveState("Bar");
		assertNotNull(saveState);

		// In the old style, 'NAME' was used as the key value and the state itself had no name.
		// In this case, getName() returns the default of 'SAVE_STATE'.
		assertEquals(SaveState.SAVE_STATE_TAG_NAME, saveState.getName());
	}

	@Test
	public void testSaveState_Unnamed_SingleLayer_RoundTrip() throws Exception {

		SaveState saveState = new SaveState();
		saveState.putInt("Foo", 21);

		SaveState restoredState = saveAndRestoreToXml(saveState);
		assertEquals(21, restoredState.getInt("Foo", -1));
		assertEquals(SaveState.SAVE_STATE_TAG_NAME, restoredState.getName());
	}

	@Test
	public void testSaveState_Named_SingleLayer_RoundTrip() throws Exception {

		SaveState saveState = new SaveState("Client_Name");
		saveState.putInt("Foo", 21);

		SaveState restoredState = saveAndRestoreToXml(saveState);
		assertEquals(21, restoredState.getInt("Foo", -1));
		assertEquals("Client_Name", restoredState.getName());
	}

	@Test
	public void testSaveState_Unnamed_DoubleLayer_RoundTrip() throws Exception {

		/*
		 	<SAVE_STATE>
			    <SAVE_STATE NAME="UNNAMED" KEY="LAYER_TWO" TYPE="SaveState">
			        <STATE NAME="layer_two.aa" TYPE="int" VALUE="5" />
			        <STATE NAME="layer_two.bb" TYPE="string" VALUE="bar" />
			    </SAVE_STATE>
			    <STATE NAME="layer_one.a" TYPE="string" VALUE="zzzz" />
			</SAVE_STATE>
		 */

		// create the hierarchy inside-out for readability
		SaveState layer2State = new SaveState();
		layer2State.putInt("layer_two.aa", 5);
		layer2State.putString("layer_two.bb", "bar");

		SaveState rootSaveState = new SaveState();
		rootSaveState.putSaveState("LAYER_TWO", layer2State);
		rootSaveState.putString("layer_one.a", "zzzz");

		SaveState restoredState = saveAndRestoreToXml(rootSaveState);

		// make sure our value is inside
		assertEquals("zzzz", restoredState.getString("layer_one.a", null));
		SaveState restoredSubState = restoredState.getSaveState("LAYER_TWO");

		assertEquals(SaveState.DEFAULT_NAME, restoredSubState.getName());

		String[] expectedNames = { "layer_two.aa", "layer_two.bb" };
		AbstractGTest.assertArraysEqualUnordered(expectedNames, restoredSubState.getNames());
		assertEquals(5, restoredSubState.getInt("layer_two.aa", 0));
		assertEquals("bar", restoredSubState.getString("layer_two.bb", ""));
	}

	@Test
	public void testSaveState_Named_DoubleLayer_RoundTrip() throws Exception {

		/*
		 	<SAVE_STATE>
			    <SAVE_STATE NAME="Client_Name" KEY="LAYER_TWO" TYPE="SaveState">
			        <STATE NAME="layer_two.aa" TYPE="int" VALUE="5" />
			        <STATE NAME="layer_two.bb" TYPE="string" VALUE="bar" />
			    </SAVE_STATE>
			    <STATE NAME="layer_one.a" TYPE="string" VALUE="zzzz" />
			</SAVE_STATE>
		 */

		// create the hierarchy inside-out for readability
		SaveState layer2State = new SaveState("Client_Name");
		layer2State.putInt("layer_two.aa", 5);
		layer2State.putString("layer_two.bb", "bar");

		SaveState rootSaveState = new SaveState();
		rootSaveState.putSaveState("LAYER_TWO", layer2State);
		rootSaveState.putString("layer_one.a", "zzzz");

		SaveState restoredState = saveAndRestoreToXml(rootSaveState);

		// make sure our value is inside
		assertEquals("zzzz", restoredState.getString("layer_one.a", null));
		SaveState restoredSubState = restoredState.getSaveState("LAYER_TWO");

		String[] expectedNames = { "layer_two.aa", "layer_two.bb" };
		AbstractGTest.assertArraysEqualUnordered(expectedNames, restoredSubState.getNames());
		assertEquals(5, restoredSubState.getInt("layer_two.aa", 0));
		assertEquals("bar", restoredSubState.getString("layer_two.bb", ""));
	}

	@Test
	public void testSaveState_Unnamed_TripleLayer_RoundTrip() throws Exception {

		/*
		<SAVE_STATE>
		    <SAVE_STATE NAME="UNNAMED" KEY="LAYER_TWO" TYPE="SaveState">
		        <SAVE_STATE NAME="UNNAMED" KEY="LAYER_THREE" TYPE="SaveState">
		            <STATE NAME="layer_three.power_on" TYPE="boolean" VALUE="false" />
		        </SAVE_STATE>
		        <STATE NAME="layer_two.a" TYPE="int" VALUE="5" />
		        <STATE NAME="layer_two.foo" TYPE="string" VALUE="bar" />
		    </SAVE_STATE>
		    <STATE NAME="layer_one.name" TYPE="string" VALUE="zzzz" />
		</SAVE_STATE>
		*/

		// create the hierarchy inside-out
		SaveState layer3State = new SaveState();
		layer3State.putBoolean("layer_three.aaa", false);

		SaveState layer2State = new SaveState();
		layer2State.putInt("layer_two.aa", 5);
		layer2State.putString("layer_two.bb", "bar");
		layer2State.putSaveState("LAYER_THREE", layer3State);

		SaveState rootSaveState = new SaveState();
		rootSaveState.putSaveState("LAYER_TWO", layer2State);
		rootSaveState.putString("layer_one.aa", "zzzz");

		SaveState restoredState = saveAndRestoreToXml(rootSaveState);

		// make sure our value is inside
		assertEquals("zzzz", restoredState.getString("layer_one.aa", null));
		SaveState restoredSubState = restoredState.getSaveState("LAYER_TWO");

		assertEquals(SaveState.DEFAULT_NAME, restoredSubState.getName());

		String[] expectedNames = { "LAYER_THREE", "layer_two.aa", "layer_two.bb" };
		AbstractGTest.assertArraysEqualUnordered(expectedNames, restoredSubState.getNames());
		assertEquals(5, restoredSubState.getInt("layer_two.aa", 0));
		assertEquals("bar", restoredSubState.getString("layer_two.bb", ""));

		SaveState restoredSubSubState = restoredSubState.getSaveState("LAYER_THREE");
		assertEquals(SaveState.DEFAULT_NAME, restoredSubSubState.getName());
		assertEquals(false, restoredSubSubState.getBoolean("layer_three.aaa", true));
	}

	@Test
	public void testSaveState_Named_TripleLayer_RoundTrip() throws Exception {

		/*
		<SAVE_STATE>
		    <SAVE_STATE NAME="Client_Name_2" KEY="LAYER_TWO" TYPE="SaveState">
		        <SAVE_STATE NAME="Client_Name_3" KEY="LAYER_THREE" TYPE="SaveState">
		            <STATE NAME="layer_three.power_on" TYPE="boolean" VALUE="false" />
		        </SAVE_STATE>
		        <STATE NAME="layer_two.a" TYPE="int" VALUE="5" />
		        <STATE NAME="layer_two.foo" TYPE="string" VALUE="bar" />
		    </SAVE_STATE>
		    <STATE NAME="layer_one.name" TYPE="string" VALUE="zzzz" />
		</SAVE_STATE>
		*/

		// create the hierarchy inside-out
		SaveState layer3State = new SaveState("Client_Name_3");
		layer3State.putBoolean("layer_three.aaa", false);

		SaveState layer2State = new SaveState("Client_Name_2");
		layer2State.putInt("layer_two.aa", 5);
		layer2State.putString("layer_two.bb", "bar");
		layer2State.putSaveState("LAYER_THREE", layer3State);

		SaveState rootSaveState = new SaveState();
		rootSaveState.putSaveState("LAYER_TWO", layer2State);
		rootSaveState.putString("layer_one.aa", "zzzz");

		SaveState restoredState = saveAndRestoreToXml(rootSaveState);

		// make sure our value is inside
		assertEquals("zzzz", restoredState.getString("layer_one.aa", null));
		SaveState restoredSubState = restoredState.getSaveState("LAYER_TWO");

		assertEquals("Client_Name_2", restoredSubState.getName());

		String[] expectedNames = { "LAYER_THREE", "layer_two.aa", "layer_two.bb" };
		AbstractGTest.assertArraysEqualUnordered(expectedNames, restoredSubState.getNames());
		assertEquals(5, restoredSubState.getInt("layer_two.aa", 0));
		assertEquals("bar", restoredSubState.getString("layer_two.bb", ""));

		SaveState restoredSubSubState = restoredSubState.getSaveState("LAYER_THREE");
		assertEquals("Client_Name_3", restoredSubSubState.getName());
		assertEquals(false, restoredSubSubState.getBoolean("layer_three.aaa", true));
	}

	@Test
	public void testSaveState_Unnamed_SiblingSaveStates_RoundTrip() throws Exception {

		/*
		<SAVE_STATE>
		    <SAVE_STATE NAME="Client_Name_2_1" KEY="LAYER_TWO_ONE" TYPE="SaveState">
		        <STATE NAME="layer_two_one.a" TYPE="int" VALUE="5" />
		    </SAVE_STATE>
		    <SAVE_STATE NAME="Client_Name_2_2" KEY="LAYER_TWO_TWO" TYPE="SaveState">
		        <STATE NAME="layer_two_two.a" TYPE="int" VALUE="5" />
		    </SAVE_STATE>
		</SAVE_STATE>
		*/

		// create the hierarchy inside-out
		SaveState layer2_1State = new SaveState("Client_Name_2_1");
		layer2_1State.putInt("layer_two_one.a", 5);

		SaveState layer2_2State = new SaveState("Client_Name_2_2");
		layer2_2State.putInt("layer_two_two.a", 6);

		SaveState rootSaveState = new SaveState();
		rootSaveState.putSaveState("LAYER_TWO_ONE", layer2_1State);
		rootSaveState.putSaveState("LAYER_TWO_TWO", layer2_2State);

		SaveState restoredState = saveAndRestoreToXml(rootSaveState);

		// make sure our value is inside
		SaveState restoredSubState1 = restoredState.getSaveState("LAYER_TWO_ONE");
		assertEquals("Client_Name_2_1", restoredSubState1.getName());

		SaveState restoredSubState2 = restoredState.getSaveState("LAYER_TWO_TWO");
		assertEquals("Client_Name_2_2", restoredSubState2.getName());

		assertEquals(5, restoredSubState1.getInt("layer_two_one.a", -1));
		assertEquals(6, restoredSubState2.getInt("layer_two_two.a", -1));
	}

	private SaveState saveAndRestoreToXml(SaveState ss) throws Exception {
		Element saveToXml = ss.saveToXml();
		return new SaveState(saveToXml);
	}
}
