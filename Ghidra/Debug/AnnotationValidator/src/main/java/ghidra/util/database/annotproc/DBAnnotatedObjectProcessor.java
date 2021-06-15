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
package ghidra.util.database.annotproc;

import java.lang.annotation.Annotation;
import java.util.*;
import java.util.stream.Collectors;

import javax.annotation.processing.*;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.*;

import ghidra.util.database.DBAnnotatedObject;
import ghidra.util.database.annot.*;

/**
 * A compile-time annotation processor for {@link DBAnnotatedObject}-related annotations.
 * 
 * Currently just performs compile-time checks. It does not generate any code, but perhaps one day,
 * it will.
 */
//@AutoService(Processor.class) // TODO: Evaluate Google's auto-service as a dependency
public class DBAnnotatedObjectProcessor extends AbstractProcessor {
	static final Set<Class<? extends Annotation>> SUPPORTED_ANNOTATIONS =
		Set.of(DBAnnotatedColumn.class, DBAnnotatedField.class, DBAnnotatedObjectInfo.class);

	private ValidationContext ctx;

	@Override
	public synchronized void init(ProcessingEnvironment env) {
		//System.err.println("HERE4");
		super.init(env);
		ctx = new ValidationContext(env);
	}

	@Override
	public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
		Map<TypeElement, DBAnnotatedObjectValidator> types = new LinkedHashMap<>();
		for (Element element : roundEnv.getElementsAnnotatedWith(DBAnnotatedObjectInfo.class)) {
			TypeElement type = (TypeElement) element; // Required by annotation Target
			types.put(type, new DBAnnotatedObjectValidator(ctx, type));
		}
		for (Element field : roundEnv.getElementsAnnotatedWith(DBAnnotatedField.class)) {
			VariableElement varField = (VariableElement) field; // Required by annotation Target
			// Fields can only be members of types, right?
			TypeElement type = (TypeElement) field.getEnclosingElement();
			DBAnnotatedObjectValidator validator =
				types.computeIfAbsent(type, t -> new DBAnnotatedObjectValidator(ctx, type));
			validator.addAnnotatedField(varField);
		}
		for (Element column : roundEnv.getElementsAnnotatedWith(DBAnnotatedColumn.class)) {
			VariableElement varColumn = (VariableElement) column; // Required by annotation Target
			// Fields can only be members of types, right?
			TypeElement type = (TypeElement) column.getEnclosingElement();
			DBAnnotatedObjectValidator validator =
				types.computeIfAbsent(type, t -> new DBAnnotatedObjectValidator(ctx, type));
			validator.addAnnotatedColumn(varColumn);
		}

		for (DBAnnotatedObjectValidator ov : types.values()) {
			ov.validate();
		}
		return true;
	}

	@Override
	public Iterable<? extends Completion> getCompletions(Element element,
			AnnotationMirror annotation, ExecutableElement member, String userText) {
		// TODO Auto-generated method stub
		return super.getCompletions(element, annotation, member, userText);
	}

	@Override
	public SourceVersion getSupportedSourceVersion() {
		return SourceVersion.latestSupported();
	}

	@Override
	public Set<String> getSupportedAnnotationTypes() {
		return SUPPORTED_ANNOTATIONS.stream().map(Class::getCanonicalName).collect(
			Collectors.toSet());
	}
}
