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
package ghidra.features.bsim.query.client;

import java.sql.SQLException;

import ghidra.features.bsim.query.LSHException;
import ghidra.features.bsim.query.description.ExecutableRecord;

/**
 * Class for managing filter elements (FilterTemplate) that need to be resolved (typically to an id)
 * before they can be converted to an SQL clause.
 *
 */
public abstract class IDSQLResolution {
	public long id1;					// First resolved id
	public long id2;					// Second resolved id

	public abstract void resolve(AbstractSQLFunctionDatabase<?> columnDatabase,
			ExecutableRecord exe) throws SQLException;

	public static class Architecture extends IDSQLResolution {			// Architecture string
		private String archName;		// Architecture name as a string

		public Architecture(String nm) {
			archName = nm;
			id1 = 0;
		}

		@Override
		public void resolve(AbstractSQLFunctionDatabase<?> columnDatabase, ExecutableRecord exe)
				throws SQLException {
			if (id1 == 0)
				id1 = columnDatabase.queryArchString(archName);
		}
	}

	public static class Compiler extends IDSQLResolution {
		private String compilerName;		// Compiler name as a string

		public Compiler(String nm) {
			compilerName = nm;
			id1 = 0;
		}

		@Override
		public void resolve(AbstractSQLFunctionDatabase<?> columnDatabase, ExecutableRecord exe)
				throws SQLException {
			if (id1 == 0)
				id1 = columnDatabase.queryCompilerString(compilerName);
		}
	}

	public static class ExeCategory extends IDSQLResolution {
		private String categoryString;			// Name of category as a string
		private String valueString;				// Value of category as a string

		public ExeCategory(String cat, String val) {
			categoryString = cat;
			valueString = val;
			id1 = 0;
			id2 = 0;
		}

		@Override
		public void resolve(AbstractSQLFunctionDatabase<?> columnDatabase, ExecutableRecord exe)
				throws SQLException {
			if (id1 == 0) {
				id1 = columnDatabase.queryCategoryString(categoryString);
				id2 = columnDatabase.queryCategoryString(valueString);
			}
		}
	}

	public static class ExternalFunction extends IDSQLResolution {
		private String exeName;			// Name of executable containing external function
		private String funcName;			// Name of external function

		public ExternalFunction(String exe, String func) {
			exeName = exe;
			funcName = func;
			id1 = 0;
		}

		@Override
		public void resolve(AbstractSQLFunctionDatabase<?> columnDatabase, ExecutableRecord exe)
				throws SQLException {
			try {
				if (id1 == 0)
					id1 = columnDatabase.recoverExternalFunctionId(exeName, funcName,
						exe.getArchitecture());
			}
			catch (LSHException ex) {
				throw new SQLException(ex.getMessage());
			}
		}
	}
}
