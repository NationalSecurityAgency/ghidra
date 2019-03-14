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
package ghidra.feature.vt.gui.util;

public class VTMatchApplyChoices {

	public static enum ReplaceChoices {
		EXCLUDE("Do Not Apply"), REPLACE("Replace");

		private String optionDisplayString;

		private ReplaceChoices(String optionDisplayString) {
			this.optionDisplayString = optionDisplayString;
		}

		@Override
		public String toString() {
			return optionDisplayString;
		}
	}

	public static enum ReplaceDefaultChoices {
		EXCLUDE("Do Not Apply"),
		REPLACE_ALWAYS("Replace Always"),
		REPLACE_DEFAULT_ONLY("Replace Default Only");

		private String optionDisplayString;

		private ReplaceDefaultChoices(String optionDisplayString) {
			this.optionDisplayString = optionDisplayString;
		}

		@Override
		public String toString() {
			return optionDisplayString;
		}
	}

	public static enum ReplaceDataChoices {
		EXCLUDE("Do Not Apply"),
		REPLACE_FIRST_DATA_ONLY("Replace First Data Only"),
		REPLACE_ALL_DATA("Replace All Data"),
		REPLACE_UNDEFINED_DATA_ONLY("Replace Undefined Data Only");

		private String optionDisplayString;

		private ReplaceDataChoices(String optionDisplayString) {
			this.optionDisplayString = optionDisplayString;
		}

		@Override
		public String toString() {
			return optionDisplayString;
		}
	}

	public static enum CommentChoices {
		EXCLUDE("Do Not Apply"),
		APPEND_TO_EXISTING("Add To Existing"),
		OVERWRITE_EXISTING("Replace Existing");

		private String optionDisplayString;

		private CommentChoices(String optionDisplayString) {
			this.optionDisplayString = optionDisplayString;
		}

		@Override
		public String toString() {
			return optionDisplayString;
		}
	}

	public static enum FunctionNameChoices {
		EXCLUDE("Do Not Apply"),
		ADD("Add"),
		ADD_AS_PRIMARY("Add As Primary"),
		REPLACE_ALWAYS("Replace Always"),
		REPLACE_DEFAULT_ONLY("Replace Default Only");

		private String optionDisplayString;

		private FunctionNameChoices(String optionDisplayString) {
			this.optionDisplayString = optionDisplayString;
		}

		@Override
		public String toString() {
			return optionDisplayString;
		}
	}

	public static enum LabelChoices {
		EXCLUDE("Do Not Apply"),
		ADD("Add"),
		ADD_AS_PRIMARY("Add As Primary"),
		REPLACE_ALL("Replace All"),
		REPLACE_DEFAULT_ONLY("Replace Default Only");

		private String optionDisplayString;

		private LabelChoices(String optionDisplayString) {
			this.optionDisplayString = optionDisplayString;
		}

		@Override
		public String toString() {
			return optionDisplayString;
		}
	}

	public static enum ParameterSourceChoices {
		ENTIRE_PARAMETER_SIGNATURE_MARKUP("Use Entire Parameters Signature"),
		INDIVIDUAL_PARAMETER_MARKUP("Use Individual Parameter Items");

		private String optionDisplayString;

		private ParameterSourceChoices(String optionDisplayString) {
			this.optionDisplayString = optionDisplayString;
		}

		@Override
		public String toString() {
			return optionDisplayString;
		}
	}

	public static enum CallingConventionChoices {
		EXCLUDE("Do Not Apply"),
		SAME_LANGUAGE("Replace If Same Language"),
		NAME_MATCH("Replace If Has Named Convention");

		private String optionDisplayString;

		private CallingConventionChoices(String optionDisplayString) {
			this.optionDisplayString = optionDisplayString;
		}

		@Override
		public String toString() {
			return optionDisplayString;
		}
	}

	public static enum FunctionSignatureChoices {
		EXCLUDE("Do Not Apply"),
		REPLACE("Replace"),
		WHEN_SAME_PARAMETER_COUNT("Replace When Same Parameter Count");

		private String optionDisplayString;

		private FunctionSignatureChoices(String optionDisplayString) {
			this.optionDisplayString = optionDisplayString;
		}

		@Override
		public String toString() {
			return optionDisplayString;
		}
	}

	public static enum ParameterDataTypeChoices {
		EXCLUDE("Do Not Apply"),
		REPLACE_UNDEFINED_DATA_TYPES_ONLY("Replace Undefined Data Types Only"),
		REPLACE("Replace");

		private String optionDisplayString;

		private ParameterDataTypeChoices(String optionDisplayString) {
			this.optionDisplayString = optionDisplayString;
		}

		@Override
		public String toString() {
			return optionDisplayString;
		}
	}

	public static enum FunctionAttributeChoices {
		EXCLUDE("Do Not Apply"),
		REPLACE("Replace"),
		WHEN_TAKING_SIGNATURE("Replace When Replacing Signature");

		private String optionDisplayString;

		private FunctionAttributeChoices(String optionDisplayString) {
			this.optionDisplayString = optionDisplayString;
		}

		@Override
		public String toString() {
			return optionDisplayString;
		}
	}

	public static enum SourcePriorityChoices {
		EXCLUDE("Do Not Apply"),
		REPLACE_DEFAULTS_ONLY("Replace Default Only"),
		REPLACE("Replace"),
		PRIORITY_REPLACE("Priority Replace");

		private String optionDisplayString;

		private SourcePriorityChoices(String optionDisplayString) {
			this.optionDisplayString = optionDisplayString;
		}

		@Override
		public String toString() {
			return optionDisplayString;
		}
	}

	public static enum HighestSourcePriorityChoices {
		USER_PRIORITY_HIGHEST("User"), IMPORT_PRIORITY_HIGHEST("Import");

		private String optionDisplayString;

		private HighestSourcePriorityChoices(String optionDisplayString) {
			this.optionDisplayString = optionDisplayString;
		}

		@Override
		public String toString() {
			return optionDisplayString;
		}
	}

}
