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
package docking.widgets.table;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;

import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

/**
 * A table that allow users to provide a list of data objects whose method can be used
 * to create columns.
 *
 * @param <T> the row object type
 */
public class AnyObjectTableModel<T> extends GDynamicColumnTableModel<T, Object> {
	private List<T> data;
	private String name;

	public AnyObjectTableModel(String modelName, Class<T> dataClass, String... methodNames) {
		this(modelName, new ArrayList<T>(), dataClass, Arrays.asList(methodNames));
	}

	public AnyObjectTableModel(String modelName, Method... methods) {
		this(modelName, new ArrayList<T>(), Arrays.asList(methods));
	}

	public AnyObjectTableModel(String modelName, List<Method> methods) {
		this(modelName, new ArrayList<T>(), methods);
	}

	public AnyObjectTableModel(String modelName, Class<T> dataClass, List<String> methodNames) {
		this(modelName, new ArrayList<T>(), dataClass, methodNames);
	}

	public AnyObjectTableModel(String modelName, List<T> data, Class<T> dataClass,
			List<String> methodNames) {
		super(new ServiceProviderStub());
		this.data = data;
		this.name = modelName;

		Objects.requireNonNull(methodNames);
		SystemUtilities.assertTrue(!methodNames.isEmpty(), "Method names must be provided");

		for (String methodName : methodNames) {
			addTableColumn(new MethodColumn(dataClass, methodName));
		}
	}

	public AnyObjectTableModel(String modelName, List<T> data, List<Method> methods) {
		super(new ServiceProviderStub());
		this.data = data;
		this.name = modelName;

		Objects.requireNonNull(methods);
		SystemUtilities.assertTrue(!methods.isEmpty(), "Methods must be provided");

		for (Method method : methods) {
			addTableColumn(new MethodColumn(method));
		}
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	@Override
	public List<T> getModelData() {
		return data;
	}

	public void setModelData(List<T> data) {
		this.data = data;
		fireTableDataChanged();
	}

	@Override
	protected TableColumnDescriptor<T> createTableColumnDescriptor() {
		return new TableColumnDescriptor<>();
	}

	@Override
	public Object getDataSource() {
		return null;
	}

	private static String fromCamelCase(String text) {
		StringBuilder buffy = new StringBuilder();

		//@formatter:off
		text.chars()
			.mapToObj(i -> (char) i)
			.forEach(c -> {
				if (c == '_') {
					buffy.append(' ');
				}
				else if (Character.isUpperCase(c)) {
					if (buffy.length() > 1) { // no space in the front
						buffy.append(' ');
					}
					buffy.append(c);
				}
				else {
					boolean wasSpace = isLastCharASpace(buffy);
					char C = maybeToUpperCase(c, wasSpace);
					buffy.append(C);
				}

			})
			;
		//@formatter:on

		buffy.replace(0, 1, buffy.substring(0, 1).toUpperCase()); // Initial cap

		return buffy.toString();
	}

	private static boolean isLastCharASpace(StringBuilder buffy) {
		if (buffy.length() == 0) {
			return false;
		}
		return buffy.charAt(buffy.length() - 1) == ' ';
	}

	private static char maybeToUpperCase(char c, boolean shouldBeUpper) {

		if (shouldBeUpper) {
			return Character.toUpperCase(c);
		}

		return c;
	}

	private class MethodColumn extends AbstractDynamicTableColumn<T, Object, Object> {
		private String name;
		private Method method;
		private Class<?> returnType;

		public MethodColumn(Class<T> dataClass, String methodName) {
			try {
				Method m = dataClass.getMethod(methodName);
				init(m);
			}
			catch (NoSuchMethodException | SecurityException e) {
				name = "No method: " + methodName;
			}
		}

		public MethodColumn(Method method) {
			init(method);
		}

		@Override
		public String getColumnDescription() {
			return null;
		}

		private void init(Method m) {
			this.method = m;
			name = method.getName();
			if (name.startsWith("get")) {
				name = name.substring(3);
			}

			name = fromCamelCase(name);
			returnType = method.getReturnType();
		}

		@SuppressWarnings("unchecked")
		@Override
		public Class<Object> getColumnClass() {
			return (Class<Object>) returnType;
		}

		@Override
		public String getColumnName() {
			return name;
		}

		@Override
		public Object getValue(T rowObject, Settings settings, Object dataSource,
				ServiceProvider sp) throws IllegalArgumentException {
			if (method == null) {
				Msg.error(this,
					"No method '" + name + "' on class" + rowObject.getClass().getSimpleName());
				return null;
			}
			try {
				return method.invoke(rowObject);
			}
			catch (IllegalAccessException | IllegalArgumentException
					| InvocationTargetException e) {
				Msg.debug(this, "Problem invoking method: " + method.getName() + " on " +
					method.getDeclaringClass().getSimpleName() + ". See nested exception", e);
			}
			return null;
		}

	}

}
