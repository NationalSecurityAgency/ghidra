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

import ghidra.util.database.DBAnnotatedObject;
import ghidra.util.database.DBCachedObjectStoreFactory.DBFieldCodec;

@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface DBAnnotatedField {
	String column();

	boolean indexed() default false;

	@SuppressWarnings("rawtypes")
	Class<? extends DBFieldCodec> codec() default DefaultCodec.class;

	static abstract class DefaultCodec<OT extends DBAnnotatedObject, FT extends db.Field>
			implements DBFieldCodec<Void, OT, FT> {
		private DefaultCodec() {
			throw new AssertionError();
		}
	}
}
