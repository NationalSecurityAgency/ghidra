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
import ghidra.util.StringUtilities;
import ghidra.util.UniversalID;
import ghidra.util.exception.AssertException;

public class DataTypeLine implements ValidatableLine {

	private String type;
	private String name;
	private String comment;
	private DataType dataType;

	private Color typeColor;
	private Color nameColor;
	private Color commentColor;

	private ValidatableLine validationLine;

	DataTypeLine(String name, String type, String comment, DataType dt) {
		this.dataType = dt;
		if (name == null) {
			name = "";
		}

		this.name = name;
		this.type = Objects.requireNonNull(type, "Type of data type cannot be null");
		this.comment = comment == null ? "" : comment;
	}

	@Override
	public ValidatableLine copy() {
		return new DataTypeLine(name, type, comment, dataType);
	}

	@Override
	public boolean isDiffColored() {
		return getTypeColor() != null || getNameColor() != null || getCommentColor() != null;
	}

	public String getType() {
		return type;
	}

	public String getName() {
		return name;
	}

	public String getComment() {
		return comment;
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

	public Color getTypeColor() {
		return typeColor;
	}

	public void setTypeColor(Color typeColor) {
		this.typeColor = typeColor;
	}

	public Color getNameColor() {
		return nameColor;
	}

	public void setNameColor(Color nameColor) {
		this.nameColor = nameColor;
	}

	public Color getCommentColor() {
		return commentColor;
	}

	public void setCommentColor(Color commentColor) {
		this.commentColor = commentColor;
	}

	void setAllColors(Color diffColor) {
		setNameColor(diffColor);
		setTypeColor(diffColor);
		setCommentColor(diffColor);
	}

	@Override
	public void updateColor(ValidatableLine otherValidatableLine, Color invalidColor) {
		if (invalidColor == null) {
			throw new NullPointerException("Color cannot be null");
		}

		if (otherValidatableLine == null) {
			setNameColor(invalidColor);
			setTypeColor(invalidColor);
			setCommentColor(invalidColor);
			return;
		}

		if (!(otherValidatableLine instanceof DataTypeLine)) {
			throw new AssertException("DataTypeLine can only be matched against other " +
				"DataTypeLine implementations.");
		}
		DataTypeLine otherLine = (DataTypeLine) otherValidatableLine;

		// note: use the other line here, so if it is a special, overridden case, then we will
		//       benefit from it's 'matches' methods
		if (!otherLine.matchesName(name)) {
			setNameColor(invalidColor);
			otherLine.setNameColor(invalidColor);
		}

		if (!otherLine.matchesType(type)) {
			setTypeColor(invalidColor);
			otherLine.setTypeColor(invalidColor);
		}

		if (!otherLine.matchesComment(comment)) {
			setCommentColor(invalidColor);
			otherLine.setCommentColor(invalidColor);
		}
	}

	boolean matchesName(String otherName) {
		return this.name.equals(otherName);
	}

	boolean matchesType(String otherType) {
		return this.type.equals(otherType);
	}

	boolean matchesComment(String otherComment) {
		return this.comment.equals(otherComment);
	}

	@Override
	public boolean isValidated() {
		return validationLine != null;
	}

	@Override
	public String getText() {
		return type + " " + name + " " + comment;
	}

	@Override
	public String toString() {

		int max = Math.max(length(type), Math.max(length(name), length(comment)));

		//@formatter:off
        return "\ntype:    " + pad(type, max) + colorString(typeColor) + 
        		"\nname:    " + pad(name, max) + colorString(nameColor) + 
        		"\ncomment: " + pad(comment, max) + colorString(commentColor) + "\n";
      //@formatter:on
	}

	private int length(String s) {
		return s == null ? 0 : s.length();
	}

	private String colorString(Color c) {
		if (c == null) {
			return "";
		}
		return " (colored)";
	}

	private String pad(String actual, int size) {
		int diff = size - actual.length();
		return StringUtilities.pad(actual, ' ', -diff);
	}

	@Override
	public boolean matches(ValidatableLine otherValidatableLine) {
		if (otherValidatableLine == null) {
			return false;
		}

		if (!(otherValidatableLine instanceof DataTypeLine)) {
			throw new AssertException("DataTypeLine can only be matched against other " +
				"DataTypeLine implementations.");
		}
		DataTypeLine otherLine = (DataTypeLine) otherValidatableLine;

		// note: use the other line here, so if it is a special, overridden case, then we will
		//       benefit from it's 'matches' methods
		return otherLine.matchesName(name) && otherLine.matchesType(type) &&
			otherLine.matchesComment(comment);
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
