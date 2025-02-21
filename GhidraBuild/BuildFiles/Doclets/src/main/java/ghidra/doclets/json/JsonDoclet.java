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
package ghidra.doclets.json;

import java.io.*;
import java.util.*;
import java.util.stream.Collectors;

import javax.lang.model.SourceVersion;
import javax.lang.model.element.*;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.TypeMirror;
import javax.lang.model.util.ElementFilter;
import javax.tools.Diagnostic.Kind;

import com.google.gson.*;
import com.sun.source.doctree.*;
import com.sun.source.util.DocTrees;

import jdk.javadoc.doclet.*;

/**
 * Doclet that outputs javadoc in JSON format (instead of HTML). Things like Python can then
 * read in the JSON and easily access all of the javadoc elements.
 * 
 * To run: gradle zipJavadocs
 */
public class JsonDoclet implements Doclet {

    private Reporter log;
    private File destDir;
    private DocletEnvironment docEnv;
    private DocTrees docTrees;

    private final Gson gson;

    public JsonDoclet() {
        this.gson = new GsonBuilder()
                .setPrettyPrinting()
                .serializeNulls()
                .create();
    }

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
                return List.of("-d");
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
        });
    }

    @Override
    public boolean run(DocletEnvironment env) {
        this.docEnv = env;
        this.docTrees = env.getDocTrees();

        // Create destination directory
        if (!validateDestinationDirectory()) {
            return false;
        }

        // Create JSON for all classes
        ElementFilter.typesIn(docEnv.getIncludedElements()).stream()
                .filter(el -> el.getKind() == ElementKind.CLASS || el.getKind() == ElementKind.INTERFACE)
                .forEach(el -> writeJsonToFile(classToJson(el), el.getQualifiedName()));

        return true;
    }

    private boolean validateDestinationDirectory() {
        if (destDir == null) {
            log.print(Kind.ERROR, "Destination directory not set");
            return false;
        }
        if (!destDir.exists() && !destDir.mkdirs()) {
            log.print(Kind.ERROR, "Failed to create destination directory at: " + destDir);
            return false;
        }
        return true;
    }

    private JsonObject classToJson(TypeElement classElement) {
        JsonObject classObj = new JsonObject();
        processClassAttributes(classElement, classObj);
        processFieldAndMethodAttributes(classElement, classObj);
        return classObj;
    }

    private void processClassAttributes(TypeElement classElement, JsonObject classObj) {
        classObj.addProperty("name", classElement.getSimpleName().toString());
        classObj.addProperty("comment", getComment(docTrees.getDocCommentTree(classElement)));
        classObj.addProperty("javadoc", getJavadoc(docTrees.getDocCommentTree(classElement)));
        classObj.addProperty("static", classElement.getModifiers().contains(Modifier.STATIC));
        addInterfaces(classElement, classObj);
        addSuperClass(classElement, classObj);
    }

    private void addInterfaces(TypeElement typeElement, JsonObject obj) {
        JsonArray interfaceArray = new JsonArray();
        typeElement.getInterfaces().stream()
                .filter(DeclaredType.class::isInstance)
                .map(DeclaredType.class::cast)
                .map(declaredType -> declaredType.asElement())
                .filter(TypeElement.class::isInstance)
                .map(TypeElement.class::cast)
                .forEach(ifaceTypeElement -> interfaceArray.add(ifaceTypeElement.getQualifiedName().toString()));

        obj.add("implements", interfaceArray);
    }

    private void addSuperClass(TypeElement typeElement, JsonObject obj) {
        if (typeElement.getSuperclass() instanceof DeclaredType declaredType) {
            if (declaredType.asElement() instanceof TypeElement typeEl) {
                obj.addProperty("extends", typeEl.getQualifiedName().toString());
            }
        }
    }

    private void processFieldAndMethodAttributes(TypeElement classElement, JsonObject classObj) {
        JsonArray fieldArray = new JsonArray();
        JsonArray methodArray = new JsonArray();

        for (Element el : classElement.getEnclosedElements()) {
            JsonObject obj = new JsonObject();
            populateElementAttributes(el, obj);

            switch (el.getKind()) {
                case FIELD -> {
                    VariableElement varElement = (VariableElement) el;
                    obj.addProperty("type_long", getTypeLong(el.asType()));
                    obj.addProperty("type_short", getTypeShort(el.asType()));
                    Object constantValue = varElement.getConstantValue();
                    if (constantValue instanceof String) {
                        constantValue = "\"" + constantValue + "\"";
                    }
                    obj.addProperty("constant_value", Objects.toString(constantValue, null));
                    fieldArray.add(obj);
                }
                case CONSTRUCTOR, METHOD -> {
                    ExecutableElement execElement = (ExecutableElement) el;
                    addParams(execElement, obj);
                    addReturn(execElement, obj);
                    addExceptions(execElement, obj);
                    methodArray.add(obj);
                }
                default -> {}
            }
        }

        classObj.add("fields", fieldArray);
        classObj.add("methods", methodArray);
    }

    private void populateElementAttributes(Element el, JsonObject obj) {
        obj.addProperty("name", el.getSimpleName().toString());
        obj.addProperty("comment", getComment(docTrees.getDocCommentTree(el)));
        obj.addProperty("javadoc", getJavadoc(docTrees.getDocCommentTree(el)));
        obj.addProperty("static", el.getModifiers().contains(Modifier.STATIC));
    }

    private void addParams(ExecutableElement execElement, JsonObject obj) {
        JsonArray paramsArray = new JsonArray();
        for (VariableElement varElement : execElement.getParameters()) {
            JsonObject paramObj = new JsonObject();
            paramObj.addProperty("name", varElement.getSimpleName().toString());
            paramObj.addProperty("type_long", getTypeLong(varElement.asType()));
            paramObj.addProperty("type_short", getTypeShort(varElement.asType()));
            paramObj.addProperty("comment", getParamComment(execElement, varElement));
            paramsArray.add(paramObj);
        }
        obj.add("params", paramsArray);
    }

    private String getParamComment(ExecutableElement execElement, VariableElement varElement) {
        String comment = "";
        DocCommentTree commentTree = docTrees.getDocCommentTree(execElement);
        if (commentTree != null) {
            for (DocTree blockTag : commentTree.getBlockTags()) {
                if (blockTag.getKind() == DocTree.Kind.PARAM) {
                    ParamTree paramTree = (ParamTree) blockTag;
                    if (paramTree.getName().getName().equals(varElement.getSimpleName())) {
                        comment = getComment(blockTag);
                        break;
                    }
                }
            }
        }
        return comment;
    }

    private void addReturn(ExecutableElement execElement, JsonObject obj) {
        JsonObject returnObj = new JsonObject();
        TypeMirror returnType = execElement.getReturnType();
        returnObj.addProperty("type_long", getTypeLong(returnType));
        returnObj.addProperty("type_short", getTypeShort(returnType));
        returnObj.addProperty("comment", getReturnComment(execElement));
        obj.add("return", returnObj);
    }

    private String getReturnComment(ExecutableElement execElement) {
        String comment = "";
        DocCommentTree commentTree = docTrees.getDocCommentTree(execElement);
        if (commentTree != null) {
            for (DocTree blockTag : commentTree.getBlockTags()) {
                if (blockTag.getKind() == DocTree.Kind.RETURN) {
                    comment = getComment(blockTag);
                }
            }
        }
        return comment;
    }

    private void addExceptions(ExecutableElement execElement, JsonObject obj) {
        JsonArray throwsArray = new JsonArray();
        for (TypeMirror thrownType : execElement.getThrownTypes()) {
            JsonObject throwObj = new JsonObject();
            String typeShort = getTypeShort(thrownType);
            throwObj.addProperty("type_long", getTypeLong(thrownType));
            throwObj.addProperty("type_short", typeShort);
            throwObj.addProperty("comment", getThrowsComment(execElement, typeShort));
            throwsArray.add(throwObj);
        }
        obj.add("throws", throwsArray);
    }

    private String getThrowsComment(ExecutableElement execElement, String typeShort) {
        String comment = "";
        DocCommentTree commentTree = docTrees.getDocCommentTree(execElement);
        if (commentTree != null) {
            for (DocTree blockTag : commentTree.getBlockTags()) {
                if (blockTag.getKind() == DocTree.Kind.THROWS) {
                    ThrowsTree throwsTree = (ThrowsTree) blockTag;
                    if (throwsTree.getExceptionName().toString().equals(typeShort)) {
                        comment = getComment(blockTag);
                        break;
                    }
                }
            }
        }
        return comment;
    }

    private String getTypeLong(TypeMirror type) {
        return type.toString();
    }

    private String getTypeShort(TypeMirror type) {
        return type.getKind() == TypeKind.DECLARED ?
                ((DeclaredType) type).asElement().getSimpleName().toString() :
                type.toString();
    }

    private String getComment(DocTree docTree) {
        return switch (docTree.getKind()) {
            case COMMENT -> ((CommentTree) docTree).getBody();
            case LINK -> ((LinkTree) docTree).getReference().getSignature();
            case PARAM -> getComment(((ParamTree) docTree).getDescription());
            case RETURN -> getComment(((ReturnTree) docTree).getDescription());
            case TEXT -> ((TextTree) docTree).getBody();
            case THROWS -> getComment(((ThrowsTree) docTree).getDescription());
            default -> "";
        };
    }

    private String getComment(List<? extends DocTree> docTreeList) {
        return docTreeList.stream()
                .map(this::getComment)
                .collect(Collectors.joining());
    }

    private String getComment(DocCommentTree docCommentTree) {
        return docCommentTree != null ? getComment(docCommentTree.getFullBody()) : "";
    }

    private String getJavadoc(DocCommentTree docCommentTree) {
        return docCommentTree != null ? docCommentTree.toString() : "";
    }

    private void writeJsonToFile(JsonObject json, Name qualifiedName) {
        File jsonFile = new File(destDir, qualifiedName.toString().replace('.', '/') + ".json");
        jsonFile.getParentFile().mkdirs();
        try (PrintWriter writer = new PrintWriter(new FileWriter(jsonFile))) {
            writer.println(gson.toJson(json));
        } catch (IOException e) {
            log.print(Kind.ERROR, "Failed to write JSON to file: " + e.getMessage());
        }
    }
}
