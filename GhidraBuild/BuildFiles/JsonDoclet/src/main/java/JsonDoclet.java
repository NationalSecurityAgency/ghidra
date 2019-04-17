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
import java.io.*;
import java.util.*;
import java.util.stream.Collectors;

import javax.lang.model.SourceVersion;
import javax.lang.model.element.*;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.TypeMirror;
import javax.lang.model.util.ElementFilter;
import javax.tools.Diagnostic.Kind;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import com.sun.source.doctree.*;
import com.sun.source.util.DocTrees;

import jdk.javadoc.doclet.*;

/**
 * Doclet that outputs javadoc in JSON format (instead of HTML).  Things like Python can then
 * read in the JSON and easily access all of the javadoc elements.
 */
@SuppressWarnings("unchecked")
public class JsonDoclet implements Doclet {

	private Reporter log;
	private File destDir;

	private DocletEnvironment docEnv;
	private DocTrees docTrees;

	@Override
	public void init(Locale locale, Reporter reporter) {
		this.log = reporter;
	}

	@Override
	public String getName() {
		return this.getClass().getSimpleName();
	}

	@Override
	public SourceVersion getSupportedSourceVersion() {
		return SourceVersion.RELEASE_11;
	}

	@Override
	public Set<? extends Option> getSupportedOptions() {
		Option[] options = { new Option() {
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
				destDir = new File(arguments.get(0));
				return true;
			}

		} };
		return new HashSet<>(Arrays.asList(options));
	}

	@Override
	public boolean run(DocletEnvironment env) {

		this.docEnv = env;
		this.docTrees = env.getDocTrees();

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

		// Create JSON for all classes
		//@formatter:off
		ElementFilter.typesIn(docEnv.getIncludedElements())
			.stream()
			.filter(el -> el.getKind().equals(ElementKind.CLASS) || el.getKind().equals(ElementKind.INTERFACE))
			.forEach(el -> writeJsonToFile(classToJson(el), el.getQualifiedName()));
		//@formatter:on

		return true;
	}

	/**
	 * Converts a class {@link TypeElement} to a {@link JSONObject}.
	 * 
	 * @param classElement the class {@link TypeElement} to convert
	 * @return A json object that represents the class.
	 */
	private JSONObject classToJson(TypeElement classElement) {
		JSONObject classObj = new JSONObject();
		processClassAttributes(classElement, classObj);
		processFieldAndMethodAttributes(classElement, classObj);
		return classObj;
	}

	/**
	 * Adds the high-level class attributes to the given json object. 
	
	 * @param classElement the class element to parse
	 * @param classObj the json object to populate
	 */
	private void processClassAttributes(TypeElement classElement, JSONObject classObj) {
		classObj.put("name", classElement.getSimpleName().toString());
		classObj.put("comment", getComment(docTrees.getDocCommentTree(classElement)));
		classObj.put("javadoc", getJavadoc(docTrees.getDocCommentTree(classElement)));
		classObj.put("static", classElement.getModifiers().contains(Modifier.STATIC));
		addInterfaces(classElement, classObj);
		addSuperClass(classElement, classObj);
	}

	/**
	 * Parses the given {@link TypeElement} for any declared interfaces and adds them to the
	 * json object.
	 * 
	 * @param typeElement the {@link TypeElement} to parse
	 * @param obj the json object to populate
	 */
	private void addInterfaces(TypeElement typeElement, JSONObject obj) {
		JSONArray interfaceArray = new JSONArray();

		//@formatter:off
		typeElement.getInterfaces()
			.stream()
			.filter(DeclaredType.class::isInstance)
			.map(DeclaredType.class::cast)
			.map(declaredType -> declaredType.asElement())
			.filter(TypeElement.class::isInstance)
			.map(TypeElement.class::cast)
			.forEach(ifaceTypeElement -> interfaceArray.add(ifaceTypeElement.getQualifiedName().toString()));
		//@formatter:on

		obj.put("implements", interfaceArray);
	}

	/**
	 * Parses the given {@link TypeElement} for any declared <i>extends</i> relationship and
	 * adds it to the json object
	 * 
	 * @param typeElement the {@link TypeElement} to parse
	 * @param obj the json object to populate
	 */
	private void addSuperClass(TypeElement typeElement, JSONObject obj) {
		if (typeElement.getSuperclass() instanceof DeclaredType) {
			DeclaredType declaredType = (DeclaredType) typeElement.getSuperclass();
			if (declaredType.asElement() instanceof TypeElement) {
				TypeElement typeEl = (TypeElement) declaredType.asElement();
				obj.put("extends", typeEl.getQualifiedName().toString());
			}
		}
	}

	/**
	 * Extracts javadoc information for all fields and methods in the given class.
	 * 
	 * @param classElement the class to parse
	 * @param classObj the json object to populate
	 */
	private void processFieldAndMethodAttributes(TypeElement classElement, JSONObject classObj) {

		JSONArray fieldArray = new JSONArray();
		JSONArray methodArray = new JSONArray();

		for (Element el : classElement.getEnclosedElements()) {

			JSONObject obj = new JSONObject();
			obj.put("name", el.getSimpleName().toString());
			obj.put("comment", getComment(docTrees.getDocCommentTree(el)));
			obj.put("javadoc", getJavadoc(docTrees.getDocCommentTree(el)));
			obj.put("static", el.getModifiers().contains(Modifier.STATIC));

			switch (el.getKind()) {
				case FIELD:
					VariableElement varElement = (VariableElement) el;
					obj.put("type_long", getTypeLong(el.asType()));
					obj.put("type_short", getTypeShort(el.asType()));
					Object constantValue = varElement.getConstantValue();
					if (constantValue instanceof String) {
						constantValue = "\"" + constantValue + "\"";
					}
					obj.put("constant_value", Objects.toString(constantValue, null)); // only applies to 'final'
					fieldArray.add(obj);
					break;
				case CONSTRUCTOR:
				case METHOD:
					ExecutableElement execElement = (ExecutableElement) el;
					addParams(execElement, obj);
					addReturn(execElement, obj);
					addExceptions(execElement, obj);
					methodArray.add(obj);
					break;
				case ANNOTATION_TYPE:
				case CLASS:
				case ENUM:
				case ENUM_CONSTANT:
				case EXCEPTION_PARAMETER:
				case INSTANCE_INIT:
				case INTERFACE:
				case LOCAL_VARIABLE:
				case MODULE:
				case OTHER:
				case PACKAGE:
				case PARAMETER:
				case RESOURCE_VARIABLE:
				case STATIC_INIT:
				case TYPE_PARAMETER:
				default:
					break;
			}
		}

		classObj.put("fields", fieldArray);
		classObj.put("methods", methodArray);
	}

	/**
	 * Parses the given {@link ExecutableElement} for any associated parameters and adds them to 
	 * the json object.
	 * 
	 * @param execElement the element to parse
	 * @param obj the json object
	 */
	private void addParams(ExecutableElement execElement, JSONObject obj) {

		JSONArray paramsArray = new JSONArray();
		for (VariableElement varElement : execElement.getParameters()) {
			JSONObject paramObj = new JSONObject();
			paramObj.put("name", varElement.getSimpleName().toString());
			paramObj.put("type_long", getTypeLong(varElement.asType()));
			paramObj.put("type_short", getTypeShort(varElement.asType()));
			String comment = "";
			DocCommentTree commentTree = docTrees.getDocCommentTree(execElement);
			if (commentTree != null) {
				for (DocTree blockTag : commentTree.getBlockTags()) {
					if (blockTag.getKind().equals(DocTree.Kind.PARAM)) {
						ParamTree paramTree = (ParamTree) blockTag;
						if (paramTree.getName().getName().equals(varElement.getSimpleName())) {
							comment = getComment(blockTag);
							break;
						}
					}
				}
			}
			paramObj.put("comment", comment);
			paramsArray.add(paramObj);
		}
		obj.put("params", paramsArray);
	}

	/**
	 * Parses the given {@link ExecutableElement} for any <code>return</code> information
	 * and adds it to the json object.
	 * 
	 * @param execElement the element to parse
	 * @param obj the json object
	 */
	private void addReturn(ExecutableElement execElement, JSONObject obj) {
		TypeMirror returnType = execElement.getReturnType();
		JSONObject returnObj = new JSONObject();
		returnObj.put("type_long", getTypeLong(returnType));
		returnObj.put("type_short", getTypeShort(returnType));
		String comment = "";
		DocCommentTree commentTree = docTrees.getDocCommentTree(execElement);
		if (commentTree != null) {
			for (DocTree blockTag : commentTree.getBlockTags()) {
				if (blockTag.getKind().equals(DocTree.Kind.RETURN)) {
					comment = getComment(blockTag);
				}
			}
		}
		returnObj.put("comment", comment);
		obj.put("return", returnObj);
	}

	/**
	 * Parses the given {@link ExecutableElement} for thrown exceptions and adds them to
	 * the json object.
	 * 
	 * @param execElement the element to parse
	 * @param obj the json object
	 */
	private void addExceptions(ExecutableElement execElement, JSONObject obj) {
		JSONArray throwsArray = new JSONArray();
		for (TypeMirror thrownType : execElement.getThrownTypes()) {
			JSONObject throwObj = new JSONObject();
			String typeLong = getTypeLong(thrownType);
			String typeShort = getTypeShort(thrownType);
			throwObj.put("type_long", typeLong);
			throwObj.put("type_short", typeShort);
			String comment = "";
			DocCommentTree commentTree = docTrees.getDocCommentTree(execElement);
			if (commentTree != null) {
				for (DocTree blockTag : commentTree.getBlockTags()) {
					if (blockTag.getKind().equals(DocTree.Kind.THROWS)) {
						ThrowsTree throwsTree = (ThrowsTree) blockTag;
						if (throwsTree.getExceptionName().toString().equals(typeShort)) {
							comment = getComment(blockTag);
							break;
						}
					}
				}
			}
			throwObj.put("comment", comment);
			throwsArray.add(throwObj);
		}
		obj.put("throws", throwsArray);
	}

	/**
	 * Gets the long type name of the given {@link TypeMirror type}.
	 * 
	 * @param type The type to get the long type name of.
	 * @return The long type name of the given {@link TypeMirror type}.
	 */
	private String getTypeLong(TypeMirror type) {
		return type.toString();
	}

	/**
	 * Gets the short type name of the given {@link TypeMirror type}.
	 * 
	 * @param type The type to get the short type name of.
	 * @return The short type name of the given {@link TypeMirror type}.
	 */
	private String getTypeShort(TypeMirror type) {
		switch (type.getKind()) {
			case DECLARED:
				return ((DeclaredType) type).asElement().getSimpleName().toString();
			default:
				return type.toString();
		}
	}

	/**
	 * Gets the comment from the given {@link DocTree}.
	 * 
	 * @param docTree The {@link DocTree} to get the comment from.
	 * @return The comment from the given {@link DocTree}.
	 */
	private String getComment(DocTree docTree) {
		switch (docTree.getKind()) {
			case COMMENT:
				return ((CommentTree) docTree).getBody();
			case LINK:
				return ((LinkTree) docTree).getReference().getSignature();
			case PARAM:
				return getComment(((ParamTree) docTree).getDescription());
			case RETURN:
				return getComment(((ReturnTree) docTree).getDescription());
			case TEXT:
				return ((TextTree) docTree).getBody();
			case THROWS:
				return getComment(((ThrowsTree) docTree).getDescription());
			default:
				return "";
		}
	}

	/**
	 * Gets the comment from the given {@link List} of  {@link DocTree}s. Each list element 
	 * represents a line.  The final comment is simply all the lines concatenated.
	 * 
	 * @param docTreeList The {@link DocTree} {@link List} to get the comment from.
	 * @return The comment from the given {@link DocTree} {@link List}.
	 */
	private String getComment(List<? extends DocTree> docTreeList) {
		return docTreeList.stream().map(e -> getComment(e)).collect(Collectors.joining());
	}

	/**
	 * Gets the comment from the given {@link DocCommentTree}.
	 * 
	 * @param docCommentTree The {@link DocCommentTree} to get the comment from.
	 * @return The comment from the given {DocCommentTree DocTree}.
	 */
	private String getComment(DocCommentTree docCommentTree) {
		if (docCommentTree != null) {
			return getComment(docCommentTree.getFullBody());
		}
		return "";
	}

	/**
	 * Gets the full unprocessed javadoc from the given {@link DocCommentTree}.
	 * 
	 * @param docCommentTree The {@link DocCommentTree} to get the javadoc from.
	 * @return the full unprocessed javadoc from the given {@link DocCommentTree}.
	 */
	private String getJavadoc(DocCommentTree docCommentTree) {
		if (docCommentTree != null) {
			return docCommentTree.toString();
		}
		return "";
	}

	/**
	 * Writes the given json to a filename based on the given qualified class name.
	 * 
	 * @param json The json to write.
	 * @param qualifiedName The qualified class name.  This name will get converted into a directory
	 *   structure.
	 */
	private void writeJsonToFile(JSONObject json, Name qualifiedName) {
		File jsonFile = new File(destDir, qualifiedName.toString().replace('.', '/') + ".json");
		jsonFile.getParentFile().mkdirs();
		try (PrintWriter writer = new PrintWriter(new FileWriter(jsonFile))) {
			writer.println(json.toJSONString());
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}
}
