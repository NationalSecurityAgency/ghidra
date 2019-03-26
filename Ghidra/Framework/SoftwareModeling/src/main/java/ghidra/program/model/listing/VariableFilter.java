/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.model.listing;

public interface VariableFilter {

	/**
	 * <code>PARAMETER_FILTER</code> matches all parameters (includes auto-params).  A variable is
	 * treated as a parameter by this filter if it implements the Parameter interface.
	 */
	public static final VariableFilter PARAMETER_FILTER = new ParameterFilter(true);

	/**
	 * <code>NONAUTO_PARAMETER_FILTER</code> matches all parameters which are not an auto-param.  A variable is
	 * treated as a parameter by this filter if it implements the Parameter interface.
	 */
	public static final VariableFilter NONAUTO_PARAMETER_FILTER = new ParameterFilter(false);

	/**
	 * <code>LOCAL_VARIABLE_FILTER</code> matches all simple stack variables.  A variable is
	 * treated as local by this filter if it does not implement the Parameter interface.
	 */
	public static final VariableFilter LOCAL_VARIABLE_FILTER = new LocalVariableFilter();

	/**
	 * <code>STACK_VARIABLE_FILTER</code> matches all simple stack variables
	 */
	public static final VariableFilter STACK_VARIABLE_FILTER = new StackVariableFilter();

	/**
	 * <code>COMPOUND_STACK_VARIABLE_FILTER</code> matches all simple or compound variables
	 * which utilize a stack storage element
	 */
	public static final VariableFilter COMPOUND_STACK_VARIABLE_FILTER =
		new CompoundStackVariableFilter();

	/**
	 * <code>REGISTER_VARIABLE_FILTER</code> matches all simple register variables
	 */
	public static final VariableFilter REGISTER_VARIABLE_FILTER = new RegisterVariableFilter();

	/**
	 * <code>MEMORY_VARIABLE_FILTER</code> matches all simple memory variables
	 */
	public static final VariableFilter MEMORY_VARIABLE_FILTER = new MemoryVariableFilter();

	/**
	 * <code>UNIQUE_VARIABLE_FILTER</code> matches all simple unique variables identified by a hash value
	 */
	public static final VariableFilter UNIQUE_VARIABLE_FILTER = new UniqueVariableFilter();

	/**
	 * Determine if the specified variable matches this filter criteria
	 * @param variable 
	 * @return true if variable satisfies the criteria of this filter
	 */
	public boolean matches(Variable variable);

	public static class ParameterFilter implements VariableFilter {

		private final boolean allowAutoParams;

		public ParameterFilter(boolean allowAutoParams) {
			this.allowAutoParams = allowAutoParams;
		}

		@Override
		public boolean matches(Variable variable) {
			if (variable instanceof Parameter) {
				Parameter p = (Parameter) variable;
				return !p.isAutoParameter() || allowAutoParams;
			}
			return false;
		}
	}

	public static class LocalVariableFilter implements VariableFilter {

		@Override
		public boolean matches(Variable variable) {
			return !(variable instanceof Parameter);
		}
	}

	public static class StackVariableFilter implements VariableFilter {

		@Override
		public boolean matches(Variable variable) {
			return variable.isStackVariable();
		}
	}

	public static class CompoundStackVariableFilter implements VariableFilter {

		@Override
		public boolean matches(Variable variable) {
			return variable.hasStackStorage();
		}
	}

	public static class RegisterVariableFilter implements VariableFilter {

		@Override
		public boolean matches(Variable variable) {
			return variable.isRegisterVariable();
		}
	}

	public static class MemoryVariableFilter implements VariableFilter {

		@Override
		public boolean matches(Variable variable) {
			return variable.isMemoryVariable();
		}
	}

	public static class UniqueVariableFilter implements VariableFilter {

		@Override
		public boolean matches(Variable variable) {
			return variable.isUniqueVariable();
		}
	}

}
