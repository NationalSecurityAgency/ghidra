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
package ghidra.app.util.html;

import java.awt.Color;
import java.util.Objects;

import ghidra.program.model.data.DataType;
import ghidra.util.UniversalID;
import ghidra.util.exception.AssertException;

public class VariableTextLine implements ValidatableLine {

	private String variableType;
	private String variableName;
	private DataType dataType;

	private Color variableTypeColor;
	private Color variableNameColor;

	private ValidatableLine validationLine;

	public VariableTextLine(String variableType, String variableName, DataType dataType) {

		if (variableName == null) {
			//throw new NullPointerException( "variable name cannot be null" );
			//variableName = "&lt;unnamed&gt;";

			// not sure what the best thing to show is; 'unnamed' was not well received
			variableName = "";
		}

		this.variableType =
			Objects.requireNonNull(variableType, "Variable type cannot be null");
		this.variableName = variableName;
		this.dataType = dataType;
	}

	@Override
	public ValidatableLine copy() {
		return new VariableTextLine(variableType, variableName, dataType);
	}

	public String getVariableType() {
		return variableType;
	}

	public String getVariableName() {
		return variableName;
	}

	public DataType getDataType() {
		return dataType;
	}

	public boolean hasUniversalId() {
		if (dataType == null) {
			return false;
		}
		UniversalID id = dataType.getUniversalID();
		return id != null && id.getValue() != 0;
	}

	@Override
	public boolean isDiffColored() {
		return getVariableTypeColor() != null || getVariableNameColor() != null;
	}

	public Color getVariableTypeColor() {
		return variableTypeColor;
	}

	public Color getVariableNameColor() {
		return variableNameColor;
	}

	boolean matchesName(String otherName) {
		return variableName.equals(otherName);
	}

	boolean matchesType(String otherType) {
		return variableType.equals(otherType);
	}

	@Override
	public boolean isValidated() {
		return validationLine != null;
	}

	@Override
	public String getText() {
		return variableType + " " + variableName;
	}

	@Override
	public String toString() {
		return getText();
	}

	@Override
	public boolean matches(ValidatableLine otherValidatableLine) {
		if (otherValidatableLine == null) {
			return false;
		}

		if (!(otherValidatableLine instanceof VariableTextLine)) {
			throw new AssertException("VariableTextLine can only be matched against other " +
				"VariableTextLine implementations.");
		}
		VariableTextLine otherLine = (VariableTextLine) otherValidatableLine;

		if (!otherLine.matchesType(variableType)) {
			return false;
		}

		if (!otherLine.matchesName(variableName)) {
			return false;
		}

		return otherLine.matchesType(variableType) && otherLine.matchesName(variableName);
	}

	@Override
	public void updateColor(ValidatableLine otherValidatableLine, Color invalidColor) {
		if (invalidColor == null) {
			throw new NullPointerException("Color cannot be null");
		}

		if (otherValidatableLine == null) {
			variableTypeColor = invalidColor;
			variableNameColor = invalidColor;
			return;
		}

		if (!(otherValidatableLine instanceof VariableTextLine)) {
			throw new AssertException("VariableTextLine can only be matched against other " +
				"VariableTextLine implementations.");
		}

		VariableTextLine otherLine = (VariableTextLine) otherValidatableLine;
		if (!otherLine.matchesType(variableType)) {
			variableTypeColor = invalidColor;
			otherLine.variableTypeColor = invalidColor;
		}

		if (!otherLine.matchesName(variableName)) {
			variableNameColor = invalidColor;
			otherLine.variableNameColor = invalidColor;
		}
	}

	void setAllColors(Color color) {
		variableTypeColor = color;
		variableNameColor = color;
	}

	@Override
	public void setValidationLine(ValidatableLine line) {
		if (validationLine == line) {
			return; // already set
		}

		this.validationLine = line;
		line.setValidationLine(this);
		updateColor(line, INVALID_COLOR);
	}
}
