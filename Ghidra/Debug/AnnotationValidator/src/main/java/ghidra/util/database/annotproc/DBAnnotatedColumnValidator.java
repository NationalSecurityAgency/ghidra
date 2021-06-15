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

public class DBAnnotatedColumnValidator extends AbstractDBAnnotationValidator {
	final VariableElement column;

	public DBAnnotatedColumnValidator(ValidationContext ctx, VariableElement column) {
		super(ctx);
		this.column = column;
	}

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
