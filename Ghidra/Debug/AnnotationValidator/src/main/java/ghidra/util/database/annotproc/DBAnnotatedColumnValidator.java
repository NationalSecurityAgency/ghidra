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

import java.util.Set;

import javax.lang.model.element.*;
import javax.tools.Diagnostic.Kind;

import ghidra.util.database.annot.DBAnnotatedColumn;

/**
 * A class for validating fields annotated with {@link DBAnnotatedColumn}.
 * 
 * <p>
 * To ensure fields annotated with {@link DBAnnotatedColumn} comply with the expected criteria for
 * database columns in Ghidra.
 * </p>
 */

public class DBAnnotatedColumnValidator extends AbstractDBAnnotationValidator {
	final VariableElement column;

	/**
	 * Construct a new {@code DBAnnotatedColumnValidator} with the specified validation context and
	 * the column element.
	 * 
	 * @param ctx the validation context
	 * @param column the field representing the column
	 */
	public DBAnnotatedColumnValidator(ValidationContext ctx, VariableElement column) {
		super(ctx);
		this.column = column;
	}

	/**
	 * Validate the annotated column field.
	 * 
	 * <p>
	 * It performs the following checks to ensure it meets the requirements for database columns:
	 * <ul>
	 * <li>The field must be of the type specified by {@code ctx.DB_OBJECT_COLUMN_ELEM}.</li>
	 * <li>The field must not be declared as {@code final}.</li>
	 * <li>The field must be declared as {@code static}.</li>
	 * <li>The enclosing type of the field must meet the criteria defined in
	 * {@code checkEnclosingType}.</li>
	 * </ul>
	 */
	public void validate() {
		if (!ctx.hasType(column, ctx.DB_OBJECT_COLUMN_ELEM)) {
			ctx.messager.printMessage(Kind.ERROR,
				String.format("@%s can only be applied to fields of type %s",
					DBAnnotatedColumn.class.getSimpleName(), ctx.DB_OBJECT_COLUMN_ELEM),
				column);
		}
		Set<Modifier> mods = column.getModifiers();
		if (mods.contains(Modifier.FINAL)) {
			ctx.messager.printMessage(Kind.ERROR,
				String.format("@%s cannot be applied to a final field",
					DBAnnotatedColumn.class.getSimpleName()),
				column);
		}
		if (!mods.contains(Modifier.STATIC)) {
			ctx.messager.printMessage(Kind.ERROR,
				String.format("@%s must be applied to a static field",
					DBAnnotatedColumn.class.getSimpleName()),
				column);
		}
		TypeElement type = (TypeElement) column.getEnclosingElement();
		checkEnclosingType(DBAnnotatedColumn.class, column, type);
	}
}
