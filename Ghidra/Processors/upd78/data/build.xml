<?xml version="1.0" encoding="UTF-8"?>

<!--
  + Compile sleigh languages within this distribution language module via Eclipse or
  + a command shell.
  + 
  +   * Eclipse: right-click on this file and choose menu item "Run As->Ant Build"
  +
  +   * From command line (requires ant install)
  +        - cd to data directory containing this file
  +        - run ant
  +
  + Sleigh compiler options are read from sleighArgs.txt.
  -->
                                     
<project name="privateBuildDistribution" default="sleigh-compile">
	
	<property name="sleigh.compile.class" value="ghidra.pcodeCPort.slgh_compile.SleighCompile"/>
	
	<target name="sleigh-compile">
	    
	    <property name="framework.path" value="../../../Framework"/>
		
		<path id="sleigh.class.path">
			<fileset dir="${framework.path}/SoftwareModeling/lib">
				<include name="*.jar"/>
			</fileset>
			<fileset dir="${framework.path}/Generic/lib">
				<include name="*.jar"/>
			</fileset>
			<fileset dir="${framework.path}/Utility/lib">
				<include name="*.jar"/>
			</fileset>
		</path>
		
		<available classname="${sleigh.compile.class}" classpathref="sleigh.class.path" property="sleigh.compile.exists"/>
			
		<fail unless="sleigh.compile.exists" />
		
		<java classname="${sleigh.compile.class}"
			classpathref="sleigh.class.path"
			fork="true"
			failonerror="true">
			<jvmarg value="-Xmx2048M"/>
			<arg value="-DBaseDir=../../../../../" />  <!-- Ghidra install directory -->
			<arg value="-i"/>
			<arg value="sleighArgs.txt"/>
			<arg value="-a"/>
			<arg value="./languages"/>
		</java>
		
 	</target>

</project>
