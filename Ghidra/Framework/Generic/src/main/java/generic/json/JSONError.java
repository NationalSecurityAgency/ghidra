/* ###
 * IP: MIT
 */
package generic.json;

public enum JSONError {

	/* Everything was fine */
	JSMN_SUCCESS,
	/* Not enough tokens were provided */
	JSMN_ERROR_NOMEM,
	/* Invalid character inside JSON string */
	JSMN_ERROR_INVAL,
	/* The string is not a full JSON packet, more bytes expected */
	JSMN_ERROR_PART
	
}
