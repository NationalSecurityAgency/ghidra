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
/*
 * Created on Nov 7, 2003
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package ghidra.app.plugin.match;

import ghidra.program.model.address.Address;

/**
 * Cheap container for match info. 
 */
public class SubroutineMatch {

	private Address[] progAAddrs;
	private Address[] progBAddrs;
	private String reason;
	/**
	 * 
	 */
	public SubroutineMatch(String reason) {
		progAAddrs = new Address[0];
		progBAddrs = new Address[0];
		this.reason = reason;
	}
	
	public boolean add( Address addr, boolean isA )
	{
		Address[] newOne;
		if( isA )
		{
			newOne = new Address[progAAddrs.length+1];
			for( int i=0; i<progAAddrs.length; i++)
				newOne[i] = progAAddrs[i];
			newOne[progAAddrs.length] = addr;
			progAAddrs = newOne;
		} else {
			newOne = new Address[progBAddrs.length+1];
			for( int i=0; i<progBAddrs.length; i++)
				newOne[i] = progBAddrs[i];
			newOne[progBAddrs.length] = addr;
			progBAddrs = newOne;			
		}	
		return true;
	}
	
	public boolean remove( Address addr, boolean isA )
	{
		if( addr == null ) return false;
		int cnt = 0;
		if( isA )
		{
			for( int i=0; i< progAAddrs.length; i++ )
			{
				if( addr.equals(progAAddrs[i]))
					progAAddrs[i] = null;
				else
					cnt++;
			}
			Address [] newOne = new Address[cnt];
			cnt = 0;
			for( int i=0; i< progAAddrs.length; i++ )
			{
				if( progAAddrs[i] != null)
					newOne[cnt++] = progAAddrs[i];
			}
			this.progAAddrs = newOne;
		} else {
			for( int i=0; i< progBAddrs.length; i++ )
			{
				if( addr.equals(progBAddrs[i]))
					progBAddrs[i] = null;
				else
					cnt++;
			}
			Address [] newOne = new Address[cnt];
			cnt = 0;
			for( int i=0; i< progBAddrs.length; i++ )
			{
				if( progBAddrs[i] != null)
					newOne[cnt++] = progBAddrs[i];
			}
			this.progBAddrs = newOne;
		}
		return false;
	}
	
	
	public String getReason()
	{
		return reason;
	}
	
	public Address[] getAAddresses(){ 
		return this.progAAddrs;
	}
	
	public Address[] getBAddresses(){ 
		return this.progBAddrs;
	}
	
	private boolean isOneToOne()
	{
		if(progAAddrs.length == 1 && progBAddrs.length == 1)
			return true;
		return false;
	}
	
	@Override
    public String toString(){
		String str = reason + " ";
		for( int i=0; i<progAAddrs.length; i++)
			str += progAAddrs[i] + ",";
		str += " --- ";
		for( int i=0; i<progBAddrs.length; i++)
			str += progBAddrs[i] + ",";
		return str;
	}

}
