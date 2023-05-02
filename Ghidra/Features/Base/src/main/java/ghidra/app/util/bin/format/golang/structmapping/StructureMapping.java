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
package ghidra.app.util.bin.format.golang.structmapping;

import java.lang.annotation.*;

/**
 * Indicates that the tagged class corresponds to a Ghidra structure.
 * <p>
 * For fixed/static length structures, an existing Ghidra structure data type will be found and
 * then bound to the tagged class, and it will control how instances of the tagged class 
 * are deserialized.  Only fields that are interesting / relevant need to be tagged with
 * a {@link FieldMapping} annotation, which causes them to be pulled into the java structure.
 * <p>
 * For {@link FieldOutput#isVariableLength() variable} length structures, a unique Ghidra 
 * structure data type will be created for each combination of field lengths, and the tagged
 * class must deserialize itself by implementing the {@link StructureReader} interface. (each
 * field that needs to be mapped into the Ghidra structure must be tagged with a {@link FieldOutput}
 * annotation)
 * <p>
 * In either case, various annotations on fields and methods will control how this structure 
 * will be marked up in the Ghidra program.
 * <p>
 * The tagged class must be {@link DataTypeMapper#registerStructure(Class) registered} with
 * the program context to enable the suite of structure mapped classes to work together when
 * applied to a Ghidra binary.
 * <p>
 * For variable length structure classes, when the struct mapping system creates a custom-fitted
 * structure to markup a specific location with its specific data, the new struct data type's name
 * will be patterned as "structurename_NN_MM_...", where NN and MM and etc are the lengths of the
 * variable length fields found in the structure. 
 * <p>
 * Structure mapped classes must have a {@link StructureContext} member variable that is tagged
 * with the {@link ContextField} annotation, and probably should have a {@link DataTypeMapper}
 * member variable (that corresponds to a more specific type of DataTypeMapper) that is also 
 * tagged with the ContextField annotation.
 * 
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface StructureMapping {
	/**
	 * Specifies the name of a Ghidra structure that the tagged class represents.  For fixed
	 * length structures, the {@link DataTypeMapper} will search for this Ghidra data type
	 * in it's configured
	 * {@link DataTypeMapper#addArchiveSearchCategoryPath(ghidra.program.model.data.CategoryPath...) archive}
	 * and 
	 * {@link DataTypeMapper#addProgramSearchCategoryPath(ghidra.program.model.data.CategoryPath...) program}
	 * search paths.
	 * 
	 * @return
	 */
	String structureName();

	@SuppressWarnings("rawtypes")
	Class<? extends StructureMarkupFunction> markupFunc() default StructureMarkupFunction.class;
}
