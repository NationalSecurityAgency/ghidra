package ghidra.app.util.bin.format.stabs;

import java.util.Arrays;
import java.util.List;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

// Couldn't figure out how to link to the id groupname in Pattern
/**
 * A factory for generating StabTokens
 * @param <E> The enum to use for accessing the StabToken Groups.
 * The enum names MUST conform to the Pattern group naming rules.
 */
public class StabsTokenizer<E extends Enum<E>> {

	private final Pattern pattern;

	/**
	 * Constructs a new StabsTokenizer
	 * @param regex the regex to use. The provided regex string is expected to have
	 * a string conversion <code>%s</code> for each value in the enum parameter.
	 * @param groups the enum class to use for grouping
	 * @see java.util.Formatter Formatter
	 */
	public StabsTokenizer(String regex, Class<E> groups) {
		Object[] groupNames = Arrays.stream(groups.getEnumConstants())
									.map(E::name)
									.toArray();
		this.pattern = Pattern.compile(String.format(regex, groupNames));
	}

	@Override
	public String toString() {
		return pattern.pattern();
	}

	/**
	 * Generates a StabToken from the provided stab string
	 * @param stab the stab string
	 * @return a new StabToken
	 */
	public StabsToken<E> getToken(String stab) {
		final Matcher matcher = pattern.matcher(stab);
		if (matcher.lookingAt()) {
			return new StabsToken<>(matcher);
		}
		throw new IllegalStateException(stab + " doesn't match the pattern "+pattern);
	}

	/**
	 * Generates a StabToken for all found matches in the provided stab string
	 * @param stab the stab string
	 * @return a new list of StabTokens
	 */
	public List<StabsToken<E>> getTokens(String stab) {
		final Matcher matcher = pattern.matcher(stab);
		return matcher.results()
					  .map(MatchResult::group)
					  .map(this::getToken)
					  .collect(Collectors.toList());
	}

	/**
	 * Checks if this StabTokenizer can tokenize the provided stab string
	 * @param stab the stab string
	 * @return true if it can StabToken can be produced from the stab
	 * @see Matcher#lookingAt()
	 */
	public boolean canTokenize(String stab) {
		return pattern.matcher(stab).lookingAt();
	}

	/**
	 * Gets the pattern being used by this StabTokenizer
	 * @return the pattern
	 */
	public Pattern getPattern() {
		return pattern;
	}
}
