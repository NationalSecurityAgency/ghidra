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
class LongReturnerTests{


   long callsReturnLongVoid(){
       long a = returnLongVoid();
       return a;
   }

   long callsReturnLongInt(int x){
       long a = returnLongInt(x);
       return a;
    }

    long callsReturnLongIntInt(int x, int y){
        long a =returnLongIntInt(x,y);
        return a;
    }

    long callsReturnLongLong(long x){
        long a= returnLongLong(x);
        return a;
    }
  
    long callsReturnLongLongLong(long x, long y){
        long a = returnLongLongLong(x,y);
        return a;
    }

    long callsReturnLongIntLong(int x, long y){
        long a = returnLongIntLong(x,y);
        return a;
    }

    int callsReturnIntIntLong(int x, long y){
        int a = returnIntIntLong(x,y);
        return a;
    }  

    long callsReturnLongLongInt(long x, int y){
        long a = returnLongLongInt(x,y);
        return a;
     }

    int callsReturnIntLongInt(long x, int y){
        int a = returnIntLongInt(x,y);
        return a;
    }

    static long staticCallsReturnLongLongInt(long x, int y){
        long a = staticReturnLongLongInt(x,y);
        return a;
    }

    static long staticCallsReturnLongIntLong(int y, long x){
        long a = staticReturnLongIntLong(y,x);
        return a;
    }




    long returnLongVoid(){
        return 1L;
    }

    long returnLongInt(int x){
        return 1L;
    }
 
    long returnLongIntInt(int x, int y){
        return 1L;
    }

    long returnLongLong(long x){
        return 1L;
    }
   
    long returnLongLongLong(long x, long y){
        return 1L;
    }

    long returnLongIntLong(int x, long y){
        return 1L;
    }
    
    int returnIntIntLong(int x, long y){
        return 1;
    }
    
    long returnLongLongInt(long x, int y){
        return 1L;
    }

    int returnIntLongInt(long x, int y){
        return 1;
    }

    static long staticReturnLongLongInt(long x, int y){
        return 1L;
    }

    static long staticReturnLongIntLong(int x, long y){
        return 1L;
    } 

}
