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

import javax.lang.model.element.*;
import javax.tools.Diagnostic.Kind;

public class AbstractDBAnnotationValidator {
	protected final ValidationContext ctx;

	public AbstractDBAnnotationValidator(ValidationContext ctx) {
		this.ctx = ctx;
	}

	protected void checkEnclosingType(Class<? extends Annotation> annotType, VariableElement field,
			TypeElement type) {
		if (type.getKind() != ElementKind.CLASS) {
			ctx.messager.printMessage(Kind.ERROR, String.format(
				"@%s can only be applied to fields in a class", annotType.getSimpleName()), field);
		}
		else if (!ctx.isSubclass(type, ctx.DB_ANNOTATED_OBJECT_ELEM)) {
			ctx.messager.printMessage(Kind.ERROR,
				String.format("@%s can only be applied within a subclass of %s",
					annotType.getSimpleName(), ctx.DB_ANNOTATED_OBJECT_ELEM),
				field);
		}
	}
}
