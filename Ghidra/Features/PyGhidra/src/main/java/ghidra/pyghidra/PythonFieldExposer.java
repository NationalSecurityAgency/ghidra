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
package ghidra.pyghidra;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.invoke.ConstantBootstraps;
import java.lang.invoke.VarHandle;
import java.lang.invoke.MethodHandles.Lookup;
import java.lang.reflect.Constructor;
import java.util.Map;

import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

/**
 * A marker interface to apply Jpype class customizations to a class.
 * 
 * The Jpype class customizations will create Python properties which can access protected fields.
 * 
 * This interface is for <b>internal use only</b> and is only public so it can be
 * visible to Python to apply the Jpype class customizations.
 */
public sealed interface PythonFieldExposer permits PyGhidraScriptProvider.PyGhidraGhidraScript,
		PyGhidraScriptProvider.PyGhidraHeadlessScript {

	/**
	 * Gets a mapping of all the explicitly exposed fields of a class.
	 * 
	 * This method is for <b>internal use only</b> and is only public so it can be
	 * called from Python.
	 * 
	 * @param cls the PythonFieldExposer class
	 * @return a map of the exposed fields
	 */
	public static Map<String, ExposedField> getProperties(
			Class<? extends PythonFieldExposer> cls) {
		try {
			return doGetProperties(cls);
		}
		catch (Throwable t) {
			Msg.error(PythonFieldExposer.class,
				"Failed to expose fields for " + cls.getSimpleName(), t);
			return Map.of();
		}
	}

	@SuppressWarnings("unchecked")
	private static Map<String, ExposedField> doGetProperties(
			Class<? extends PythonFieldExposer> cls)
			throws Throwable {
		ExposedFields fields = cls.getAnnotation(ExposedFields.class);
		String[] names = fields.names();
		Class<?>[] types = fields.types();
		if (names.length != types.length) {
			throw new AssertException("Improperly applied ExposedFields on " + cls.getSimpleName());
		}

		Constructor<? extends ExposedField> c =
			fields.exposer().getConstructor(String.class, Class.class);
		Map.Entry<String, ExposedField>[] properties = new Map.Entry[names.length];
		for (int i = 0; i < names.length; i++) {
			properties[i] = Map.entry(names[i], c.newInstance(names[i], types[i]));
		}
		return Map.ofEntries(properties);
	}

	/**
	 * An annotation for exposing protected fields of a class to Python
	 */
	@Target(ElementType.TYPE)
	@Retention(RetentionPolicy.RUNTIME)
	static @interface ExposedFields {
		/**
		 * @return the {@link ExposedField} subclass with access to the protected fields
		 */
		public Class<? extends ExposedField> exposer();

		/**
		 * @return the names of the protected fields to be exposed
		 */
		public String[] names();

		/**
		 * @return the types of the protected fields to be exposed
		 */
		public Class<?>[] types();
	}

	/**
	 * Base class for making a protected field accessible from Python.
	 * 
	 * Child classes are to be defined inside the class containing the fields to be exposed.
	 * The only requirement of the child class is to provide a {@link Lookup} with access
	 * to the protected fields, to the {@link ExposedField} constructor as shown below.
	 * 
	 * {@snippet lang="java" :
	 * public class ExampleClass implements PythonFieldExposer {
	 *     protected int counter = 0;
	 * 
	 *     private static class ExposedField extends PythonFieldExposer.ExposedField {
	 *         public ExposedField(String name, Class<?> type) {
	 *             super(MethodHandles.lookup().in(ExampleClass.class), name, type);
	 *         }
	 *     }
	 * }
	 * }
	 */
	static abstract class ExposedField {
		private final VarHandle handle;

		/**
		 * Constructs a new {@link ExposedField}
		 * 
		 * @param lookup the {@link Lookup} with access to the protected field
		 * @param name the name of the protected field
		 * @param type the type of the protected field
		 */
		protected ExposedField(Lookup lookup, String name, Class<?> type) {
			handle = ConstantBootstraps.fieldVarHandle(lookup, name, VarHandle.class,
				lookup.lookupClass(), type);
		}

		/**
		 * Gets the field value
		 * 
		 * @param self the instance containing the field
		 * @return the field value
		 */
		public final Object fget(Object self) {
			return handle.get(self);
		}

		/**
		 * Sets the field value
		 * 
		 * @param self the instance containing the field
		 * @param value the field value
		 */
		public final void fset(Object self, Object value) {
			handle.set(self, value);
		}
	}
}
