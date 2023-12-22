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
package ghidra.app.util.viewer.field;

import ghidra.framework.options.CustomOption;
import ghidra.framework.options.GProperties;

/**
 * An option class that is used by the {@link EolExtraCommentsPropertyEditor} to load and save 
 * option settings.
 */
public class EolExtraCommentsOption implements CustomOption {

	private static final String BASE_KEY = "extraComment";
	private static final String KEY_REPETABLE = BASE_KEY + "Repeatable";
	private static final String KEY_REF_REPETABLE = BASE_KEY + "RefRepeatable";
	private static final String KEY_AUTO_DATA = BASE_KEY + "AutoData";
	private static final String KEY_AUTO_FUNCTION = BASE_KEY + "AutoFunction";
	private static final String KEY_USE_ABBRAVIATED = BASE_KEY + "UseAbbreviated";

	private EolEnablement repeatable = EolEnablement.DEFAULT;
	private EolEnablement refRepeatable = EolEnablement.DEFAULT;
	private EolEnablement autoFunction = EolEnablement.DEFAULT;
	private EolEnablement autoData = EolEnablement.DEFAULT;

	private boolean useAbbreviatedComments = true;

	public EolExtraCommentsOption() {
		// required for persistence
	}

	public EolEnablement getRepeatable() {
		return repeatable;
	}

	public void setRepeatable(EolEnablement priority) {
		repeatable = priority;
	}

	public EolEnablement getRefRepeatable() {
		return refRepeatable;
	}

	public void setRefRepeatable(EolEnablement priority) {
		refRepeatable = priority;
	}

	public EolEnablement getAutoData() {
		return autoData;
	}

	public void setAutoData(EolEnablement priority) {
		autoData = priority;
	}

	public EolEnablement getAutoFunction() {
		return autoFunction;
	}

	public void setAutoFunction(EolEnablement priority) {
		autoFunction = priority;
	}

	public boolean useAbbreviatedComments() {
		return useAbbreviatedComments;
	}

	public void setUseAbbreviatedComments(boolean b) {
		useAbbreviatedComments = b;
	}

	public boolean alwaysShowAutoComments() {
		return autoData == EolEnablement.ALWAYS || autoFunction == EolEnablement.ALWAYS;
	}

	public boolean isShowingRefRepeatables(boolean hasOtherComments) {
		return isShowing(refRepeatable, hasOtherComments);
	}

	public boolean isShowingRepeatables(boolean hasOtherComments) {
		return isShowing(repeatable, hasOtherComments);
	}

	public boolean isShowingAutoComments(boolean hasOtherComments) {

		if (alwaysShowAutoComments()) {
			return true;
		}

		if (isShowing(autoData, hasOtherComments)) {
			return true;
		}

		return isShowing(autoFunction, hasOtherComments);
	}

	private boolean isShowing(EolEnablement enablement, boolean hasExistingComments) {
		return enablement == EolEnablement.ALWAYS ||
			(enablement == EolEnablement.DEFAULT && !hasExistingComments);
	}

	@Override
	public void readState(GProperties properties) {
		repeatable = properties.getEnum(KEY_REPETABLE, EolEnablement.DEFAULT);
		refRepeatable = properties.getEnum(KEY_REF_REPETABLE, EolEnablement.DEFAULT);
		autoData = properties.getEnum(KEY_AUTO_DATA, EolEnablement.DEFAULT);
		autoFunction = properties.getEnum(KEY_AUTO_FUNCTION, EolEnablement.DEFAULT);
		useAbbreviatedComments = properties.getBoolean(KEY_USE_ABBRAVIATED, true);
	}

	@Override
	public void writeState(GProperties properties) {
		properties.putEnum(KEY_REPETABLE, repeatable);
		properties.putEnum(KEY_REF_REPETABLE, refRepeatable);
		properties.putEnum(KEY_AUTO_DATA, autoData);
		properties.putEnum(KEY_AUTO_FUNCTION, autoFunction);
		properties.putBoolean(KEY_USE_ABBRAVIATED, useAbbreviatedComments);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((autoData == null) ? 0 : autoData.hashCode());
		result = prime * result + ((autoFunction == null) ? 0 : autoFunction.hashCode());
		result = prime * result + ((refRepeatable == null) ? 0 : refRepeatable.hashCode());
		result = prime * result + ((repeatable == null) ? 0 : repeatable.hashCode());
		result = prime * result + (useAbbreviatedComments ? 1231 : 1237);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		EolExtraCommentsOption other = (EolExtraCommentsOption) obj;
		if (autoData != other.autoData) {
			return false;
		}
		if (autoFunction != other.autoFunction) {
			return false;
		}
		if (refRepeatable != other.refRepeatable) {
			return false;
		}
		if (repeatable != other.repeatable) {
			return false;
		}
		if (useAbbreviatedComments != other.useAbbreviatedComments) {
			return false;
		}
		return true;
	}

}
