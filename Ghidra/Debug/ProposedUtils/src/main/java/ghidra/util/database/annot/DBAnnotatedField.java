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
package ghidra.util.database.annot;

import java.lang.annotation.*;

import db.Field;
import ghidra.util.database.DBAnnotatedObject;
import ghidra.util.database.DBCachedObjectStoreFactory.DBFieldCodec;

/**
 * Mark a field to be stored in a table column
 *
 * @see DBAnnotatedObject
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface DBAnnotatedField {
	/**
	 * The name of the column
	 * 
	 * <p>
	 * There should be a {@link DBAnnotatedColumn} annotation with the same column name
	 */
	String column();

	/**
	 * True to index the column
	 */
	boolean indexed() default false;

	/**
	 * True to use sparse storage
	 * 
	 * <p>
	 * If the {@link Field} used by the codec does not support null values, this can be set to true
	 * to allow null values.
	 */
	boolean sparse() default false;

	/**
	 * Specify a custom codec
	 * 
	 * <p>
	 * This is not required for types supported directly by a {@link Field}.
	 * 
	 * @see DBFieldCodec
	 */
	@SuppressWarnings("rawtypes")
	Class<? extends DBFieldCodec> codec() default DefaultCodec.class;

	/**
	 * A placeholder class
	 *
	 * <p>
	 * A reference to this class type indicates that {@link DBAnnotatedField#codec()} was not set.
	 * The framework will instead check for a built-in codec.
	 */
	static abstract class DefaultCodec<OT extends DBAnnotatedObject, FT extends db.Field>
			implements DBFieldCodec<Void, OT, FT> {
		private DefaultCodec() {
			throw new AssertionError();
		}
	}
}
