package ghidra.app.util.bin.format.stabs;

import java.util.regex.Matcher;

public class StabsToken<E extends Enum<E>> {

	private final Matcher matcher;

	/**
	 * Constructs a new StabsToken
	 * @param matcher the tokens matcher
	 */
	public StabsToken(Matcher matcher) {
		this.matcher = matcher;
	}

	@Override
	public String toString() {
		return matcher.group();
	}

	/**
	 * Gets the matcher group for this Enum Value
	 * @param value the group's enum value
	 * @return the matched group
	 * @see Matcher#group(String)
	 */
	public String get(E value) {
		return matcher.group(value.name());
	}

	/**
	 * Gets the character at the start of the matched group
	 * @param value the group's enum value
	 * @return the character at the start of the matched group
	 * @see Matcher#group(String)
	 */
	public char getChar(E value) {
		return matcher.group(value.name()).charAt(0);
	}

	/**
	 * Gets the starting index of the matched group
	 * @param value the group's enum value
	 * @return the starting index
	 * @see Matcher#start(String)
	 */
	public int start(E value) {
		return matcher.start(value.name());
	}

	/**
	 * Gets the ending index of the matched group
	 * @param value the group's enum value
	 * @return the ending index
	 * @see Matcher#end(String)
	 */
	public int end(E value) {
		return matcher.end(value.name());
	}

	/**
	 * Gets the matcher being used for this StabToken
	 * @return the matcher
	 */
	public Matcher getMatcher() {
		return matcher;
	}

	/**
	 * Gets the length of this token
	 * @return the length
	 */
	public int getLength() {
		return matcher.group().length();
	}
}
