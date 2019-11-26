/* ###
 * IP: MIT
 */
package generic.json;

public class JSONToken {
	
	public JSONType type;
	public int start;
	public int end;
	public int size;

	/**
	 * JSON token description.
	 * @param type	the token type (object, array, string etc.)
	 * @param start	the start position in JSON data string
	 * @param end   the end position in JSON data string
	 */
	public JSONToken(JSONType type, int start, int end) {
		setType(type);
		setStart(start);
		setEnd(end);
		setSize(0);
	}
	
	public void setType(JSONType type) {
		this.type = type;
	}
	public JSONType getType() {
		return type;
	}
	public void setStart(int start) {
		this.start = start;
	}
	public int getStart() {
		return start;
	}
	public void setEnd(int end) {
		this.end = end;
	}
	public int getEnd() {
		return end;
	}
	public void setSize(int size) {
		this.size = size;
	}
	public int getSize() {
		return size;
	}
	public void incSize() {
		size++;
	}
}
