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
package ghidra.app.cmd.label;

import ghidra.app.util.NamespaceUtils;
import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;

/**
 * This class attempts to create a namespace for each token in the provided
 * string.  Thus, when providing a namespace string, do not include the name
 * of anything other than namespaces, such as the name of a symbol.
 * <p>
 * <a id="examples"></a>
 * Example strings:
 * <ul>
 *     <li>global{@link Namespace#DELIMITER ::}child1{@link Namespace#DELIMITER ::}child2
 *     <li>child1
 * </ul>
 * <p>
 * <a id="assumptions"></a>
 * To view the assumptions for creating namespaces from a path string, see
 * the {@link NamespaceUtils} class.
 *
 *
 * @since  Tracker Id 619
 * @see    NamespaceUtils
 */
public class CreateNamespacesCmd implements Command {

	private String statusMsg;

	private Namespace rootNamespace;
	private String namespacesString;
	private SourceType source;

	private Namespace leafNamespace;

	/**
	 * Takes a namespace string that will be parsed and the results of which
	 * will be used for creating the namespaces if they do not exist.
	 * <p>
	 * Calling this constructor is equivalent to calling:
	 * <pre>
	 * Command command = new CreateNamespacesCmd( namespaceString, null );
	 * </pre>
	 *
	 * @param namespacesString The string to be parsed.
	 * @param source the source of the namespace
	 * @see   <a href="#examples">example format</a>
	 * @see   <a href="#assumptions">assumptions</a>
	 */
	public CreateNamespacesCmd(String namespacesString, SourceType source) {
		this(namespacesString, null, source);
	}

	/**
	 * Takes a namespace string that will be parsed and the results of which
	 * will be used for creating the namespaces if they do not exist.
	 *
	 * @param namespacesString The string to be parsed.
	 * @param parentNamespace The namespace to be used as the starting parent
	 *        of the namespaces that will be created.
	 * @param source the source of the namespace
	 * @throws NullPointerException if <code>namespaceString</code> is <code>null</code>.
	 * @see   <a href="#examples">example format</a>
	 * @see   <a href="#assumptions">assumptions</a>
	 */
	public CreateNamespacesCmd(String namespacesString, Namespace parentNamespace, SourceType source) {

		if (namespacesString == null) {
			throw new NullPointerException("Cannot create namespaces from a "
					+ "null namespacesString value.");
		}

		this.namespacesString = namespacesString;
		this.rootNamespace = parentNamespace;
		this.source = source;
	}

	/**
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {

		try {
			leafNamespace =
					NamespaceUtils.createNamespaceHierarchy(namespacesString, rootNamespace,
						(Program) obj, source);

			if (leafNamespace != null) {
				return true;
			}
		}
		catch (InvalidInputException e) {
			// this means that a name was not of a valid format,
			// so let's bounce that back to the user
			statusMsg = e.getMessage();
			return false;
		}

		statusMsg = "Unable to create namespaces from namespace " + "string: " + namespacesString;
		return false;
	}

	/**
	 * Returns the newly created namespace or null if one was not created.
	 * @return the newly created namespace or null if one was not created.
	 */
	public Namespace getNamespace() {
		return leafNamespace;
	}

	@Override
	public String getStatusMsg() {
		return statusMsg;
	}

	@Override
	public String getName() {
		return "Create Namespaces";
	}

}
