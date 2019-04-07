/* ###
 * IP: MIT
 */
package generic.json;

import java.util.*;

import ghidra.util.Msg;
import ghidra.util.NumericUtilities;


/*
this file is a modification of jsmn.
its copyright and MIT license follow.

Copyright (c) 2010 Serge A. Zaitsev

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/


public class JSONParser {

	/**
	 * JSON parser. Contains an array of token blocks available. Also stores
	 * the string being parsed now and current position in that string
	 */

	static boolean JSMN_STRICT = false;
	
	int pos; /* offset in the JSON string */
	int toknext; /* next token to allocate */
	int toksuper; /* suporior token node, e.g parent object or array */
    int ndx = 0;

	/**
	 * Create JSON parser over an array of tokens
	 */
	//static void jsmn_init(jsmn_parser *parser);

	/**
	 * Run JSON parser. It parses a JSON data string into and array of tokens, each describing
	 * a single JSON object.
	 */
	//static jsmnerr_t jsmn_parse(jsmn_parser *parser, const char *js, 
	//		jsmntok_t *tokens, unsigned int num_tokens);

	/**
	 * Creates a new parser based over a given  buffer with an array of tokens 
	 * available.
	 */
	public JSONParser() {
		pos = 0;
		toknext = 0;
		toksuper = -1;
	}

	/**
	 * Allocates a fresh unused token from the token pull.
	 */
	JSONToken allocateToken(List<JSONToken> tokens, JSONType type, int start, int end) {
		JSONToken token = new JSONToken(type, start, end);
		tokens.add(token);
		toknext = tokens.size();
		return token;
	}

	/**
	 * Fills next available token with JSON primitive.
	 */
	JSONError parsePrimitive(char [] js, List<JSONToken> tokens) {
		int start;
	
		start = pos;
	
		boolean found = false;
		if (JSMN_STRICT) {
			for (; js[pos] != '\0'; pos++) {
				switch (js[pos]) {
					case ','  : 
					case ']'  : 
					case '}' :
						found = true;
						break;
				}
				if (found) break;
				if (js[pos] < 32) {
					pos = start;
					return JSONError.JSMN_ERROR_INVAL;
				}
			}
			if (!found) {
				/* In strict mode primitive must be followed by a comma/object/array */
				pos = start;
				return JSONError.JSMN_ERROR_PART;
			}
		} else {
			for (; js[pos] != '\0'; pos++) {
				switch (js[pos]) {
					/* In strict mode primitive must be followed by "," or "}" or "]" */
					case '\t' :
					case '\r' : 
					case '\n' : 
					case ' ' : 
					case ':': 
					case ','  : 
					case ']'  : 
					case '}' :
						found = true;
						break;
				}
				if (found) break;
				if (js[pos] < 32) {
					pos = start;
					return JSONError.JSMN_ERROR_INVAL;
				}
			}
		}
	
		allocateToken(tokens, JSONType.JSMN_PRIMITIVE, start, pos);
		pos--;
		return JSONError.JSMN_SUCCESS;
	}

	/**
	 * Filsl next token with JSON string.
	 */
	JSONError parseString(char [] js, List<JSONToken> tokens) {
		int i;
	
		int start = pos;
	
		pos++;
	
		/* Skip starting quote */
		for (; pos < js.length; pos++) {
			char c = js[pos];
	
			/* Quote: end of string */
			if (c == '\"') {
				allocateToken(tokens, JSONType.JSMN_STRING, start+1, pos);
				return JSONError.JSMN_SUCCESS;
			}
	
			/* Backslash: Quoted symbol expected */
			if (c == '\\') {
				pos++;
				switch (js[pos]) {
					/* Allowed escaped symbols */
					case '\"': case '/' : case '\\' : case 'b' :
					case 'f' : case 'r' : case 'n'  : case 't' :
						break;
					/* Allows escaped symbol XXXX */
					case 'u':
						for(i = 0; i < 4; i++){
							pos++;
							if(!isxdigit(js[pos])){
								pos = start;
								return JSONError.JSMN_ERROR_INVAL;
							}
						}
						break;
					/* Unexpected symbol */
					default:
						pos = start;
						return JSONError.JSMN_ERROR_INVAL;
				}
			}
		}
		pos = start;
		return JSONError.JSMN_ERROR_PART;
	}

	/**
	 * Parse JSON string and fill tokens.
	 */
	public JSONError parse(char [] js, List<JSONToken> tokens) {
		JSONError r;
		int i;
		JSONToken token;
		
		for (; pos < js.length; pos++) {
			char c ;
			JSONType type;
	
			c = js[pos];
			switch (c) {
				case '{': case '[':
					token = allocateToken(tokens,
							c == '{' ? JSONType.JSMN_OBJECT : JSONType.JSMN_ARRAY,
							pos, -1);
					if (toksuper != -1) {
						tokens.get(toksuper).incSize();
					}
					toksuper = toknext - 1;
					break;
				case '}': case ']':
					type = (c == '}' ? JSONType.JSMN_OBJECT : JSONType.JSMN_ARRAY);
					for (i = toknext - 1; i >= 0; i--) {
						token = tokens.get(i);
						if (token.start != -1 && token.end == -1) {
							if (token.type != type) {
								return JSONError.JSMN_ERROR_INVAL;
							}
							toksuper = -1;
							token.end = pos + 1;
							break;
						}
					}
					/* Error if unmatched closing bracket */
					if (i == -1) {
						return JSONError.JSMN_ERROR_INVAL;
					}
					for (; i >= 0; i--) {
						token = tokens.get(i);
						if (token.start != -1 && token.end == -1) {
							toksuper = i;
							break;
						}
					}
					break;
				case '\"':
					r = parseString(js, tokens);
					if (r != JSONError.JSMN_SUCCESS) return r;
					if (toksuper != -1) {
						tokens.get(toksuper).incSize();
					}
					break;
				case '\t' : case '\r' : case '\n' : case ':' : case ',': case ' ': 
					break;
				/* In strict mode primitives are: numbers and booleans */
				case '-': case '0': case '1' : case '2': case '3' : case '4':
				case '5': case '6': case '7' : case '8': case '9':
				case 't': case 'f': case 'n' :
					r = parsePrimitive(js, tokens);
					if (r != JSONError.JSMN_SUCCESS) return r;
					if (toksuper != -1)
						tokens.get(toksuper).incSize();
					break;
				/* In non-strict mode every unquoted value is a primitive */
				default:
					if (JSMN_STRICT) {
						r = parsePrimitive(js, tokens);
						if (r != JSONError.JSMN_SUCCESS) return r;
						if (toksuper != -1) {
							tokens.get(toksuper).incSize();
						}
					} else {
						return JSONError.JSMN_ERROR_INVAL;
					}
					break;
			}
		}
	
		for (i = toknext - 1; i >= 0; i--) {
			/* Unmatched opened object or array */
			JSONToken test = tokens.get(i);
			if (test.start != -1 && test.end == -1) {
				return JSONError.JSMN_ERROR_PART;
			}
		}
	
		return JSONError.JSMN_SUCCESS;
	}


	String expands(String s) {
//		if (s.contains("\\")) {
//			Msg.error(this, "hmmm");
//		}
		return s;
	}
	
//		int c;
//		char *r, *w, *z;
//		unsigned long nlen;
//		unsigned short u;
//		unsigned i;
//		Str *rv;
//	
//		rv = mkstr(s, len);
//		r = s;
//		w = strdata(rv);
//		z = s+len;
//		while(r < z){
//			if(r[0] != '\\'){
//				*w++ = *r++;
//				continue;
//			}
//	
//			/* escape sequence */
//			r++;
//			switch(*r){
//			case '"':
//				c = '\"';
//				r++;
//				break;
//			case '\\':
//				c = '\\';
//				r++;
//				break;
//			case '/':
//				c = '/';
//				r++;
//				break;
//			case 'b':
//				c = '\b';
//				r++;
//				break;
//			case 'f':
//				c = '\f';
//				r++;
//				break;
//	 		case 'n':
//				c = '\n';
//				r++;
//				break;
//			case 'r':
//				c = '\r';
//				r++;
//				break;
//			case 't':
//				c = '\t';
//				r++;
//				break;
//			case 'u':
//				/* assume jsmn_parse verified we have 4 hex digits */
//				r++;
//				u = 0;
//				for(i = 0; i < 4; i++){
//					u <<= 4;
//					if(*r >= 'A' && *r <= 'F')
//						u += *r-'A'+10;
//					else if(*r >= 'a' && *r <= 'f')
//						u += *r-'a'+10;
//					else
//						u += *r-'0';
//					r++;
//				}
//				if(u > 255)
//					return 0;
//				c = (char)u;
//				break;
//			default:
//				return 0;
//			}
//			*w++ = c;
//		}
//		nlen = w-strdata(rv);
//		rv = mkstr(strdata(rv), nlen);
//		return mkvalstr(rv);

	public Object convert(char [] s, List<JSONToken> t)
	{
		Object rv = null, k, v;
		int i;
		JSONToken tp;
	
		if (ndx == t.size()) {
			System.out.println("array overflow in JSON parser");
		}
		tp = t.get(ndx++);
		String tstr = new String(s, tp.start, tp.end-tp.start);
		
		switch(tp.type){
		case JSMN_OBJECT:
			HashMap<Object, Object> tab = new HashMap<Object, Object>();
			if(tp.size%2 != 0) {
				Msg.error(this, "invalid json object");
				return null;
			}
			for(i = 0; i < tp.size/2; i++){
				k = convert(s, t);
				v = convert(s, t);
				tab.put(k, v);
			}
			rv = tab;
			break;
		case JSMN_ARRAY:
			List<Object> l = new ArrayList<Object>();
			for(i = 0; i < tp.size; i++)
				l.add(convert(s, t));
			rv = l;
			break;
		case JSMN_PRIMITIVE:
			i = tp.start;
			switch(s[tp.start]){
			case 't':
				Msg.error(this, "what is this? "+tstr);
				//rv = mkvalcval2(cval1);
				break;
			case 'f':
				Msg.error(this, "what is this? "+tstr);
				//rv = mkvalcval2(cval0);
				break;
			case 'n':
				//rv = null;
				break;
			case '-':
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				rv = NumericUtilities.parseLong(tstr);
				break;
			default:
				Msg.error(this, "invalid json primitive: "+tstr);
				return null;
			}
			break;
		case JSMN_STRING:
			rv = expands(tstr);
			if (rv == null){
				Msg.error(this, "invalid json string: "+tstr);
			}
			break;
		default:
			throw new RuntimeException("invalid json type: "+tp.type);
		}
	
		return rv;
	}

	private static boolean isxdigit(char b) {
		switch (b) {
			case '0': case '1' : case '2': case '3' : case '4':
			case '5': case '6': case '7' : case '8': case '9':
			case 'A': case 'B': case 'C' : case 'D': case 'E' : case 'F':
			case 'a': case 'b': case 'c' : case 'd': case 'e' : case 'f':
				return true;
			default:
				return false;
		}
	}

//	public static void main(String[] args) throws IOException {
//	    
//	    GhidraApplication.initialize( new HeadlessGhidraApplicationConfiguration() );
//        
//		JSONParser parser = new JSONParser();
//		BufferedReader in = openReader();
//		
//		int n = 4096;
//		char [] cbuf = new char[n];
//		int read = in.read(cbuf);
//		if (read < 2) {
//			Msg.error(null, "No input found");
//			return;
//		}
//
//		List<Object> objs = new ArrayList<Object>();
//		List<JSONToken> tokens = new ArrayList<JSONToken>();
//	
//		JSONError r = parser.parse(cbuf, tokens);
//	
//		switch(r){
//		case JSMN_SUCCESS:
//			break;
//		case JSMN_ERROR_NOMEM:
//			Msg.error(null, "out of memory");
//			return;
//		case JSMN_ERROR_INVAL:
//			Msg.error(null, "invalid json input");
//			return;
//		case JSMN_ERROR_PART:
//			Msg.error(null, "incomplete json input");
//			return;
//		default:
//			Msg.error(null, "json parser returned undefined status");
//			return;
//		}
//		if(tokens.get(0).start == -1){
//			Msg.error(null, "invalid json input");
//			return;
//		}
//		ndx = 0;
//		while (ndx <tokens.size()) {
//			Object obj = parser.convert(cbuf, tokens);
//			objs.add(obj);
//		}
//		System.out.println("end of parsing");
//		return;
//	}
//	
//	public static BufferedReader openReader() {
//		return new BufferedReader(new InputStreamReader(System.in));
//	}

}
