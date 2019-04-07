/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.util;

import ghidra.program.model.address.Address;


/**
 * Exception thrown when an attempt is made to translate an address
 * from one program into an equivalent address in another program.
 */
public class AddressTranslationException extends RuntimeException {
	
	Address address;
	AddressTranslator translator;

    /**
     * Construct a new AddressTranslationException with no message
     */
    public AddressTranslationException() {
        super();
    }
    
    /**
     * Construct a new AddressTranslationException with the given message
     *
     * @param msg    the exception message
     */
    public AddressTranslationException(String msg) {
        super(msg);
    }
    
    /**
     * Construct a new AddressTranslationException with the given address and translator.
     * The message will indicate there is a conflict between the two data types.
     *
     * @param address    the first of the two conflicting data types. 
     * (The new data type.)
     * @param translator    the second of the two conflicting data types. 
     * (The existing data type.)
     */
    public AddressTranslationException(Address address, AddressTranslator translator) {
        super("Cannot translate address \"" +address.toString() + "\" in program \"" + 
                translator.getSourceProgram().getDomainFile().getName()+ "\" to address in program \"" + 
                translator.getDestinationProgram().getDomainFile().getName() + "\".\n");
    	this.address = address;
    	this.translator = translator;
    }

	public Address getAddress() {
		return address;
	}

	public AddressTranslator getTranslator() {
		return translator;
	}

}

