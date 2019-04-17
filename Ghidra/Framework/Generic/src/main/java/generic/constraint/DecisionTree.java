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

import java.io.*;
import java.util.*;

import org.xml.sax.*;

import generic.jar.ResourceFile;
import ghidra.xml.*;

/**
 * A decisionTree is used to find property values that are determined by traversing a tree
 * of constraints. Each node in the tree has an associated constraint.  If the constraint is
 * satisfied for a given test object, then its child nodes are tested to find more and more
 * specific results.  When either there are no children in a node or none of the children's 
 * constraints are satisfied or by traversing those that are satisfied did not result in find
 * a property match, the current node is check to see if it has a value for the property being
 * search.  If so, that result is added as a Decision.
 * 
 * <P> There can be multiple paths where all constraints a matched resulting in multiple possible
 * decisions.</P>
 * <P> A non-leaf node can have properties as well, that serve as a default if it's constraint
 * is satisfied, but not of its children is satisfied or resulted in a decision.</P>
 *
 * @param <T> the type of object that the constraints are checked against.
 */
public class DecisionTree<T> {
	private DecisionNode<T> root;
	private Map<String, Class<? extends Constraint<T>>> constraintClassMap;
	private Set<String> propertyNameSet;

	public DecisionTree() {
		root = new RootDecisionNode<T>();
		constraintClassMap = new HashMap<String, Class<? extends Constraint<T>>>();
		propertyNameSet = new HashSet<String>();
	}

	/**
	 * Searches the decision tree for values of given property name that match the constraints
	 * within this tree.
	 * @param testObject the object that the constraints are test against.
	 * @param propertyName the name of the property whose values are being collected.
	 * @return a DecisionSet containing all the values of the given property whose path in the
	 * tree matched all the constraints for the given test object.
	 */
	public DecisionSet getDecisionsSet(T testObject, String propertyName) {
		DecisionSet decisionSet = new DecisionSet(propertyName);
		root.populateDecisions(testObject, decisionSet, propertyName);
		return decisionSet;
	}

	/**
	 * Registers a constraint class to be recognized from an xml constraint specification file.
	 * @param name the name of the constraint which is also the xml tag value.
	 * @param constraintClass the constraint type which will be initialized from the xml constraint
	 * specification file.
	 */
	public void registerConstraintType(String name, Class<? extends Constraint<T>> constraintClass) {
		constraintClassMap.put(name, constraintClass);
	}

	/**
	 * Registers a property name.  Every tag in an xml constraint file (except the root tag which
	 * is unused) must be either a constraint name or a property name. 
	 * @param propertyName the name of a valid property to be expected in an xml constraints file.
	 */
	public void registerPropertyName(String propertyName) {
		propertyNameSet.add(propertyName);
	}

	/**
	 * Loads the tree from an xml data contained within an input stream. Note: this method can be
	 * called multiple times, with each call appending to the existing tree.
	 * @param name the name of the input source so that decisions can be traced back to 
	 * the appropriate xml constraints source.
	 * @param stream the InputStream from which to read an xml constraints specification.
	 * @throws IOException if an I/O problem occurs reading from the stream.
	 * @throws XmlParseException if the XML is not property formatted or a tag that is not
	 * a constraint name or property name is encountered.
	 */
	public void loadConstraints(String name, InputStream stream) throws IOException,
			XmlParseException {

		XmlPullParser parser;
		try {
			parser = new NonThreadedXmlPullParserImpl(stream, name, new XMLErrorHandler(), false);
		}
		catch (SAXException e) {
			throw new XmlParseException("Sax Exception", e);
		}
		parser.next();  // skip root element start
		processSubContraintsAndProperties(root, parser);

	}

	/**
	 * Loads the tree from an xml constraint file. Note: this method can be called multiple times,
	 * with each call appending to the existing tree. 
	 * @param file the file that contains the xml for the constraint.
	 * @throws IOException if an I/O problem occurs reading from the stream.
	 * @throws XmlParseException if the XML is not property formatted or a tag that is not
	 * a constraint name or property name is encountered.
	 */
	public void loadConstraints(ResourceFile file) throws FileNotFoundException, IOException,
			XmlParseException {

		InputStream inputStream = file.getInputStream();
		String name = file.getName();

		loadConstraints(name, inputStream);

		inputStream.close();
	}

	private void processSubContraintsAndProperties(DecisionNode<T> parent, XmlPullParser parser)
			throws XmlParseException {

		XmlElement element = parser.next();

		while (!element.isEnd()) {
			Constraint<T> constraint = readConstraint(element);
			if (constraint != null) {
				DecisionNode<T> node = parent.getOrCreateNodeForContraint(constraint);
				processSubContraintsAndProperties(node, parser);
			}
			else if (propertyNameSet.contains(element.getName())) {
				processPropertyElement(parent, element, parser);
			}
			else {
				throw new XmlParseException("Unknown element tag: " + element.getName());
			}
			element = parser.next();
		}
	}

	private Constraint<T> getConstraint(String name) throws XmlParseException {
		Class<? extends Constraint<T>> constraintClass = constraintClassMap.get(name);
		if (constraintClass == null) {
			return null;
		}
		try {
			return constraintClass.newInstance();
		}
		catch (Exception e) {
			throw new XmlParseException(
				"Can't create constraint instance for class " + constraintClass.getName(), e);
		}
	}

	private void processPropertyElement(DecisionNode<T> node, XmlElement element,
			XmlPullParser parser) throws XmlParseException {

		String propertyName = element.getName();

		XmlElement nextElement = parser.next();
		if (!nextElement.isEnd()) {
			throw new XmlParseException("Expected end tag for property " + propertyName);
		}
		node.setProperty(propertyName, nextElement.getText(), parser.getName());
	}

	private Constraint<T> readConstraint(XmlElement element) throws XmlParseException {
		String name = element.getName();
		Constraint<T> constraint = getConstraint(name);
		if (constraint == null) {
			return null;
		}
		constraint.loadConstraintData(new ConstraintData(element.getAttributes()));
		return constraint;
	}

	private static class XMLErrorHandler implements ErrorHandler {
		@Override
		public void error(SAXParseException exception) throws SAXException {
			throw new SAXException("Error: " + exception);
		}

		@Override
		public void fatalError(SAXParseException exception) throws SAXException {
			throw new SAXException("Fatal error: " + exception);
		}

		@Override
		public void warning(SAXParseException exception) throws SAXException {
			throw new SAXException("Warning: " + exception);
		}
	}

}
