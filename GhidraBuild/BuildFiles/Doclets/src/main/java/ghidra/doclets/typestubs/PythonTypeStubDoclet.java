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
package ghidra.doclets.typestubs;

import java.io.*;
import java.util.*;

import javax.lang.model.SourceVersion;
import javax.lang.model.element.*;
import javax.lang.model.util.ElementFilter;
import javax.lang.model.util.Elements;
import javax.lang.model.util.Types;
import javax.tools.Diagnostic.Kind;

import com.sun.source.doctree.DeprecatedTree;
import com.sun.source.doctree.DocCommentTree;
import com.sun.source.doctree.DocTree;
import com.sun.source.doctree.LinkTree;
import com.sun.source.doctree.StartElementTree;
import com.sun.source.doctree.TextTree;

import jdk.javadoc.doclet.*;

/**
 * Doclet that outputs Python pyi files.<p/>
 *
 * To run: gradle createPythonTypeStubs
 */
public class PythonTypeStubDoclet implements Doclet {

	private Reporter log;
	private File destDir;

	private DocletEnvironment docEnv;
	private JavadocConverter docConverter;
	private Set<String> processedPackages;
	private Set<String> topLevelPackages;
	private boolean useAllTypes = false;
	private boolean useProperties = true;
	private boolean ghidraMode = false;

	@Override
	public void init(Locale locale, Reporter reporter) {
		this.log = reporter;
	}

	@Override
	public String getName() {
		return getClass().getSimpleName();
	}

	@Override
	public SourceVersion getSupportedSourceVersion() {
		return SourceVersion.RELEASE_21;
	}

	@Override
	public Set<? extends Option> getSupportedOptions() {
		return Set.of(new Option() {
			@Override
			public int getArgumentCount() {
				return 1;
			}

			@Override
			public String getDescription() {
				return "the destination directory";
			}

			@Override
			public Kind getKind() {
				return Option.Kind.STANDARD;
			}

			@Override
			public List<String> getNames() {
				return Arrays.asList("-d");
			}

			@Override
			public String getParameters() {
				return "directory";
			}

			@Override
			public boolean process(String option, List<String> arguments) {
				destDir = new File(arguments.get(0)).getAbsoluteFile();
				return true;
			}

		},
			new Option() {
				@Override
				public int getArgumentCount() {
					return 0;
				}

				@Override
				public String getDescription() {
					return "enables Ghidra specific output";
				}

				@Override
				public Kind getKind() {
					return Option.Kind.OTHER;
				}

				@Override
				public List<String> getNames() {
					return Arrays.asList("-ghidra");
				}

				@Override
				public String getParameters() {
					return "";
				}

				@Override
				public boolean process(String option, List<String> arguments) {
					ghidraMode = true;
					return true;
				}

			},
			new Option() {
				@Override
				public int getArgumentCount() {
					return 0;
				}

				@Override
				public String getDescription() {
					return "enables generation of properties from get/set/is methods";
				}

				@Override
				public Kind getKind() {
					return Option.Kind.OTHER;
				}

				@Override
				public List<String> getNames() {
					return Arrays.asList("-properties");
				}

				@Override
				public String getParameters() {
					return "";
				}

				@Override
				public boolean process(String option, List<String> arguments) {
					useProperties = true;
					return true;
				}

			});
	}

	@Override
	public boolean run(DocletEnvironment env) {

		docEnv = env;
		docConverter = new JavadocConverter(env, log);

		processedPackages = new HashSet<>();
		topLevelPackages = new HashSet<>();

		// Create destination directory
		if (destDir == null) {
			log.print(Kind.ERROR, "Destination directory not set");
			return false;
		}
		if (!destDir.exists()) {
			if (!destDir.mkdirs()) {
				log.print(Kind.ERROR, "Failed to create destination directory at: " + destDir);
				return false;
			}
		}

		Elements elements = docEnv.getElementUtils();
		Set<ModuleElement> modules = ElementFilter.modulesIn(docEnv.getSpecifiedElements());
		if (!modules.isEmpty()) {
			useAllTypes = true;
			modules.stream()
					.map(ModuleElement::getDirectives)
					.flatMap(List::stream)
					// only exported packages
					.filter(d -> d.getKind() == ModuleElement.DirectiveKind.EXPORTS)
					.map(ModuleElement.ExportsDirective.class::cast)
					// only exported to ALL-UNNAMED
					.filter(export -> export.getTargetModules() == null)
					.map(ModuleElement.ExportsDirective::getPackage)
					.map((el) -> new PythonTypeStubPackage(this, el))
					.forEach(PythonTypeStubPackage::process);
			return true;
		}

		Set<PackageElement> packages = ElementFilter.packagesIn(docEnv.getSpecifiedElements());
		if (!packages.isEmpty()) {
			useAllTypes = true;
			packages.stream()
					.map((el) -> new PythonTypeStubPackage(this, el))
					.forEach(PythonTypeStubPackage::process);
			return true;
		}

		// it is not safe to use parallelStream :(
		ElementFilter.typesIn(docEnv.getSpecifiedElements())
				.stream()
				.map(elements::getPackageOf)
				.distinct()
				.map((el) -> new PythonTypeStubPackage(this, el))
				.forEach(PythonTypeStubPackage::process);

		// ghidra docs always explicitly specifies the types
		// so we only need to check the option here
		if (ghidraMode) {
			GhidraBuiltinsBuilder builder = new GhidraBuiltinsBuilder(this);
			builder.process();
		}

		return true;
	}

	/**
	 * Prints all the imports in the provided collection<p/>
	 *
	 * If a provided import is not included in the output of this doclet, "#type: ignore"
	 * will be appended to the import. This prevents the type checker from treating the
	 * import as an error if the package is not found.
	 *
	 * @param printer the printer
	 * @param packages the packages to import
	 */
	void printImports(PrintWriter printer, Collection<PackageElement> packages) {
		for (PackageElement pkg : packages) {
			String name = PythonTypeStubElement.sanitizeQualifiedName(pkg);
			printer.print("import ");
			printer.print(name);
			if (!isIncluded(pkg)) {
				printer.println(" # type: ignore");
			}
			else {
				printer.println();
			}
		}
	}

	/**
	 * Checks if the provided element is deprecated
	 *
	 * @param el the element to check
	 * @return true if the element is deprecated
	 */
	boolean isDeprecated(Element el) {
		return docEnv.getElementUtils().isDeprecated(el);
	}

	/**
	 * Gets the ElementUtils for the current doclet environment
	 *
	 * @return the ElementUtils
	 */
	Elements getElementUtils() {
		return docEnv.getElementUtils();
	}

	/**
	 * Gets an appropriate message to be used in the warnings.deprecated decorator
	 *
	 * @param el the deprecated element
	 * @return the deprecation message or null if no deprecation reason is documented
	 */
	String getDeprecatedMessage(Element el) {
		DocCommentTree tree = docConverter.getJavadocTree(el);
		if (tree == null) {
			return null;
		}

		DeprecatedTree deprecatedTag = tree.getBlockTags()
				.stream()
				.filter(tag -> tag.getKind() == DocTree.Kind.DEPRECATED)
				.map(DeprecatedTree.class::cast)
				.findFirst()
				.orElse(null);
		if (deprecatedTag == null) {
			return null;
		}

		String res = getPlainDocString(deprecatedTag.getBody());
		// NOTE: this must be a safe string literal
		return getStringLiteral(res);
	}

	/**
	 * Checks if the provided element is specified to be included by this doclet
	 *
	 * @param element the element to check
	 * @return
	 */
	boolean isSpecified(Element element) {
		return useAllTypes || docEnv.getSpecifiedElements().contains(element);
	}

	/**
	 * Gets the TypeUtils for the current doclet environment
	 *
	 * @return the TypeUtils
	 */
	Types getTypeUtils() {
		return docEnv.getTypeUtils();
	}

	/**
	 * Gets the output directory for the doclet
	 *
	 * @return the output directory
	 */
	File getDestDir() {
		return destDir;
	}

	/**
	 * Gets the documentation for the provided element
	 *
	 * @param el the element
	 * @return the elements documentation
	 */
	String getJavadoc(Element el) {
		return docConverter.getJavadoc(el);
	}

	/**
	 * Checks if this element has any documentation
	 *
	 * @param el the element
	 * @return true if this element has documentation
	 */
	boolean hasJavadoc(Element el) {
		DocCommentTree tree = docConverter.getJavadocTree(el);
		if (tree == null) {
			return false;
		}
		return !tree.getFullBody().toString().isBlank();
	}

	/**
	 * Checks if this element has the provided Javadoc tag
	 *
	 * @param el the element
	 * @param kind the tag kind
	 * @return true if this element uses the provided Javadoc tag
	 */
	boolean hasJavadocTag(Element el, DocTree.Kind kind) {
		DocCommentTree tree = docConverter.getJavadocTree(el);
		if (tree == null) {
			return false;
		}

		Optional<?> res = tree.getFullBody()
				.stream()
				.map(DocTree::getKind)
				.filter(kind::equals)
				.findFirst();

		if (res.isPresent()) {
			return true;
		}

		return tree.getBlockTags()
				.stream()
				.map(DocTree::getKind)
				.filter(kind::equals)
				.findFirst()
				.isPresent();
	}

	/**
	 * Adds the provided package to the set of processed packages<p/>
	 *
	 * This will create any additional required namespace packages
	 *
	 * @param pkg the package being processed
	 */
	void addProcessedPackage(PackageElement pkg) {
		String name = pkg.getQualifiedName().toString();
		addProcessedPackage(PythonTypeStubElement.sanitizeQualifiedName(name));
	}

	/**
	 * Checks if the properties or ghidra options have been enabled
	 *
	 * @return true if either options are enabled
	 */
	boolean isUsingPythonProperties() {
		return useProperties;
	}

	/**
	 * Gets an appropriate string literal for the provided value<p/>
	 *
	 * The resulting String contains the value as required to be used in Java source code
	 *
	 * @param value the constant value
	 * @return an appropriate String literal for the constant value
	 */
	String getStringLiteral(Object value) {
		return docEnv.getElementUtils().getConstantExpression(value);
	}

	/**
	 * Checks if the provided package is included in the doclet output
	 *
	 * @param el the package element
	 * @return true if the package is included
	 */
	private boolean isIncluded(PackageElement el) {
		return docEnv.isIncluded(el);
	}

	/**
	 * Creates a namespace package for the provided package if one does not yet exist
	 *
	 * @param pkg the package to create
	 */
	private void createNamespacePackage(String pkg) {
		int index = pkg.indexOf('.');
		if (index != -1) {
			pkg = pkg.substring(0, index) + "-stubs" + pkg.substring(index);
		}
		else {
			pkg += "-stubs";
		}

		File fp = new File(destDir, pkg.replace('.', '/') + "/__init__.pyi");
		try {
			fp.getParentFile().mkdirs();
			fp.createNewFile();
		}
		catch (IOException e) {
			// ignored
		}
	}

	/**
	 * Adds the provided package to the set of processed packages<p/>
	 *
	 * A namespace package will be created if necessary
	 *
	 * @param pkg the package being processed
	 */
	private void addProcessedPackage(String pkg) {
		if (processedPackages.add(pkg)) {
			createNamespacePackage(pkg);
			int index = pkg.lastIndexOf('.');
			if (index != -1) {
				addProcessedPackage(pkg.substring(0, index));
			}
			else {
				topLevelPackages.add(pkg);
			}
		}
	}

	/**
	 * Gets the docstring for the provided tags without markup
	 *
	 * @param tags the list of doclet tags
	 * @return the docstring without any markup
	 */
	private static String getPlainDocString(List<? extends DocTree> tags) {
		StringBuilder builder = new StringBuilder();
		int ignoreDepth = 0;
		for (DocTree tag : tags) {
			switch (tag.getKind()) {
				case LINK:
				case LINK_PLAIN:
					LinkTree link = (LinkTree) tag;
					List<? extends DocTree> label = link.getLabel();
					if (!label.isEmpty()) {
						builder.append(getPlainDocString(label));
					}
					else {
						String sig = link.getReference().getSignature().replaceAll("#", ".");
						if (sig.startsWith(".")) {
							sig = sig.substring(1);
						}
						builder.append(sig);
					}
					break;
				case TEXT:
					TextTree text = (TextTree) tag;
					if (ignoreDepth == 0) {
						builder.append(text.getBody());
					}
					break;
				case START_ELEMENT:
					StartElementTree start = (StartElementTree) tag;
					if (!start.isSelfClosing()) {
						ignoreDepth++;
					}
					break;
				case END_ELEMENT:
					ignoreDepth--;
					break;
				default:
					break;
			}
		}
		return builder.toString();
	}
}
