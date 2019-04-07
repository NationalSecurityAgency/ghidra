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
package generic.constraint;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.awt.Color;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import generic.constraint.DecisionNode.PropertyValue;
import generic.test.AbstractGenericTest;

public class DecisionTreeTest extends AbstractGenericTest {

	//@formatter:off
	String constraintXML = 
	" <ROOT>    " +
	"	<NAME>UNKNOWN</NAME>                             " +
	"	<RED VALUE=\"255\">                            " +
	"		<BLUE VALUE=\"255\">						   " +
	"			<GREEN VALUE=\"255\">				   " +
	"				<NAME>WHITE</NAME>			   " +
	"			</GREEN>							   " +
	"		</BLUE>                                " +
	"		<BLUE VALUE=\"0\">						   " +
	"			<GREEN VALUE=\"255\">				   " +
	"				<NAME>YELLOW</NAME>			   " +
	"			</GREEN>							   " +
	"		</BLUE>                                " +
	"	</RED>                                     " +
	"	<RED VALUE=\"0\">                              " +
	"		<BLUE VALUE=\"255\">						   " +
	"			<GREEN VALUE=\"255\">				   " +
	"				<NAME>CYAN</NAME>			   " +
	"			</GREEN>							   " +
	"		</BLUE>                                " +
	"	</RED>                                     " +
 	" </ROOT>                                       ";
	
	String constraintXML2 = 
	" <ROOT>                                        " +
	"	<RED VALUE=\"255\">                            " +
	"		<BLUE VALUE=\"255\">						   " +
	"			<GREEN VALUE=\"0\">                    " +
	"				<NAME>PURPLE</NAME>            " +
	"			</GREEN>	                           " +
	"		</BLUE>                                " +
	"		<BLUE VALUE=\"0\">						   " +
	"			<GREEN VALUE=\"0\">                    " +
	"				<NAME>RED   </NAME>            " +
	"			</GREEN>	                           " +
	"		</BLUE>                                " +
	"	</RED>                                     " +
	"	<BLUE VALUE=\"0\">                              " +
	"		<RED VALUE=\"255\">						   " +
	"			<GREEN VALUE=\"255\">                    " +
	"				<NAME>YELLOW2</NAME>            " +
	"			</GREEN>	                           " +
	"		</RED>                                " +
	"	</BLUE>                                     " +
 	" </ROOT>                                       ";

 	//@formatter:on
	private DecisionTree<Color> decisionTree;

	public DecisionTreeTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		decisionTree = new DecisionTree<Color>();
		decisionTree.registerConstraintType("BLUE", BlueColorConstraint.class);
		decisionTree.registerConstraintType("GREEN", GreenColorConstraint.class);
		decisionTree.registerConstraintType("RED", RedColorConstraint.class);
		decisionTree.registerPropertyName("NAME");

		InputStream is = new ByteArrayInputStream(constraintXML.getBytes());
		decisionTree.loadConstraints("ColorXML1", is);

		InputStream is2 = new ByteArrayInputStream(constraintXML2.getBytes());
		decisionTree.loadConstraints("ColorXML2", is2);

	}

	@Test
	public void testTreeBuild() {
		@SuppressWarnings("unchecked")
		DecisionNode<Color> root = (DecisionNode<Color>) getInstanceField("root", decisionTree);

		List<DecisionNode<Color>> children = getChildren(root);
		assertEquals(3, children.size());
		DecisionNode<Color> child = children.get(0);
		Constraint<Color> constraint = getConstraint(child);
		assertTrue(constraint instanceof RedColorConstraint);
		assertTrue(getPropertyMap(child).isEmpty());

		List<DecisionNode<Color>> grandChildren = getChildren(child);
		assertEquals(2, grandChildren.size());
		DecisionNode<Color> grandChild = grandChildren.get(0);
		constraint = getConstraint(grandChild);
		assertTrue(constraint instanceof BlueColorConstraint);
		assertTrue(getPropertyMap(grandChild).isEmpty());

		List<DecisionNode<Color>> grandGrandChildren = getChildren(grandChild);
		assertEquals(2, grandGrandChildren.size());
		DecisionNode<Color> grandGrandChild = grandGrandChildren.get(0);
		constraint = getConstraint(grandGrandChild);
		assertTrue(constraint instanceof GreenColorConstraint);
		assertTrue(getChildren(grandGrandChild).isEmpty());
		Map<String, PropertyValue> propertyMap = getPropertyMap(grandGrandChild);
		assertEquals("WHITE", propertyMap.get("NAME").value);
	}

	@Test
	public void testMatchFromFirstXML() {
		Color c = Color.WHITE;
		DecisionSet decisionSet = decisionTree.getDecisionsSet(c, "NAME");
		List<Decision> decisions = decisionSet.getDecisions();
		assertEquals(1, decisions.size());
		Decision decision = decisions.get(0);
		assertEquals("WHITE", decision.getValue());
		assertEquals("Red value = 255\nBlue value = 255\nGreen value = 255\n",
			decision.getDescisionPathString());
		assertEquals("ColorXML1", decision.getSource());
	}

	@Test
	public void testMatchFromAdditionalXML() {
		Color c = new Color(255, 0, 255);
		DecisionSet decisionSet = decisionTree.getDecisionsSet(c, "NAME");
		List<Decision> decisions = decisionSet.getDecisions();
		assertEquals(1, decisions.size());
		Decision decision = decisions.get(0);
		assertEquals("PURPLE", decision.getValue());
		assertEquals("Red value = 255\nBlue value = 255\nGreen value = 0\n",
			decision.getDescisionPathString());
		assertEquals("ColorXML2", decision.getSource());
	}

	@Test
	public void testMatchMultiple() {
		Color c = new Color(255, 255, 0);
		DecisionSet decisionSet = decisionTree.getDecisionsSet(c, "NAME");
		List<Decision> decisions = decisionSet.getDecisions();
		assertEquals(2, decisions.size());
		Decision decision = decisions.get(0);
		assertEquals("YELLOW", decision.getValue());
		assertEquals("Red value = 255\nBlue value = 0\nGreen value = 255\n",
			decision.getDescisionPathString());
		assertEquals("ColorXML1", decision.getSource());

		decision = decisions.get(1);
		assertEquals("YELLOW2", decision.getValue());
		assertEquals("Blue value = 0\nRed value = 255\nGreen value = 255\n",
			decision.getDescisionPathString());
		assertEquals("ColorXML2", decision.getSource());
	}

	@Test
	public void testNoMatchUsingDefault() {
		Color c = new Color(100, 100, 100);
		DecisionSet decisionSet = decisionTree.getDecisionsSet(c, "NAME");
		List<Decision> decisions = decisionSet.getDecisions();
		assertEquals(1, decisions.size());
		Decision decision = decisions.get(0);
		assertEquals("UNKNOWN", decision.getValue());
		assertEquals("", decision.getDescisionPathString());
	}

	@SuppressWarnings("unchecked")
	private Map<String, PropertyValue> getPropertyMap(DecisionNode<Color> node) {
		return (Map<String, PropertyValue>) getInstanceField("propertyMap", node);
	}

	@SuppressWarnings("unchecked")
	private Constraint<Color> getConstraint(DecisionNode<Color> node) {
		return (Constraint<Color>) getInstanceField("constraint", node);
	}

	@SuppressWarnings("unchecked")
	private List<DecisionNode<Color>> getChildren(DecisionNode<Color> node) {
		return (List<DecisionNode<Color>>) getInstanceField("children", node);
	}

	static class RedColorConstraint extends Constraint<Color> {

		private int redValue;

		public RedColorConstraint() {
			super("RED");
		}

		@Override
		public boolean isSatisfied(Color t) {
			return t.getRed() == redValue;
		}

		@Override
		public void loadConstraintData(ConstraintData data) {
			redValue = data.getInt("VALUE");
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null) {
				return false;
			}
			if (obj.getClass() != getClass()) {
				return false;
			}
			RedColorConstraint other = (RedColorConstraint) obj;
			return redValue == other.redValue;
		}

		@Override
		public String getDescription() {
			return "Red value = " + redValue;
		}
	}

	static class GreenColorConstraint extends Constraint<Color> {

		private int greenValue;

		public GreenColorConstraint() {
			super("GREEN");
		}

		@Override
		public boolean isSatisfied(Color t) {
			return t.getGreen() == greenValue;
		}

		@Override
		public void loadConstraintData(ConstraintData data) {
			greenValue = data.getInt("VALUE");
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null) {
				return false;
			}
			if (obj.getClass() != getClass()) {
				return false;
			}
			GreenColorConstraint other = (GreenColorConstraint) obj;
			return greenValue == other.greenValue;
		}

		@Override
		public String getDescription() {
			return "Green value = " + greenValue;
		}
	}

	static class BlueColorConstraint extends Constraint<Color> {

		private int blueValue;

		public BlueColorConstraint() {
			super("BLUE");
		}

		@Override
		public boolean isSatisfied(Color t) {
			return t.getBlue() == blueValue;
		}

		@Override
		public void loadConstraintData(ConstraintData data) {
			blueValue = data.getInt("VALUE");
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null) {
				return false;
			}
			if (obj.getClass() != getClass()) {
				return false;
			}
			BlueColorConstraint other = (BlueColorConstraint) obj;
			return blueValue == other.blueValue;
		}

		@Override
		public String getDescription() {
			return "Blue value = " + blueValue;
		}

	}
}
