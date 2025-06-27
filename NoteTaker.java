//Creates notes about a function
//@author Kai Jun
//@category 
//@keybinding
//@menupath
//@toolbar

import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;

public class NoteTaker extends GhidraScript {

	@Override
	protected void run() throws Exception {
		//TODO: Add script code here
		String programName = currentProgram.getName();
		
		//TODO: Create a file browser to select location to place notes
		File directory = new File("/home/user/Desktop/".concat(programName));
		if(!directory.exists()) {
			boolean created = directory.mkdir();
			if (!created) {
				println("Failed to create directory");
				return;
			}
		}
		
		Function myFunction = getFunctionContaining(currentLocation.getAddress());
		String functionName = myFunction.getName();
		FileWriter myWriter = new FileWriter(directory.getPath() + "/" + functionName + ".md");
		// Properties
		myWriter.write("---");
		myWriter.write(System.lineSeparator());
		String functionAddress = myFunction.getEntryPoint().toString().toUpperCase();
		String defaultFunctionName = "FUN_" + functionAddress;
		// Aliases
		myWriter.write("aliases:");
		myWriter.write(System.lineSeparator());
		myWriter.write("  - " + defaultFunctionName);
		myWriter.write(System.lineSeparator());
		myWriter.write("  - " + functionName);
		myWriter.write(System.lineSeparator());
		
		// Address
		myWriter.write("address: " + "\"0x" + functionAddress + "\"");
		myWriter.write(System.lineSeparator());
		
		// References
		Set<Function> incomingRef = myFunction.getCallingFunctions(null);
		Set<Function> outgoingRef = myFunction.getCalledFunctions(null);
		
		Iterator<Function> incomingRefIter = incomingRef.iterator();
		myWriter.write("called by:");
		myWriter.write(System.lineSeparator());
		while(incomingRefIter.hasNext()) {
			myWriter.write("  - " + incomingRefIter.next().getName());
			myWriter.write(System.lineSeparator());
		}
		
		Iterator<Function> outgoingRefIter = outgoingRef.iterator();
		myWriter.write("calls:");
		myWriter.write(System.lineSeparator());
		while(outgoingRefIter.hasNext()) {
			myWriter.write("  - " + outgoingRefIter.next().getName());
			myWriter.write(System.lineSeparator());
		}
		
		myWriter.write("---");
		myWriter.write(System.lineSeparator());
		// End Properties
		
		myWriter.write("Function uses the following data types:");
		myWriter.write(System.lineSeparator());
		
	    List<DataType> allTypes = new ArrayList<>();  
	    allTypes.add(myFunction.getReturnType());  
	      
	    for (Parameter param : myFunction.getParameters()) {  
	        allTypes.add(param.getDataType());  
	    }  
	      
	    for (Variable var : myFunction.getLocalVariables()) {  
	        allTypes.add(var.getDataType());  
	    }  
	      
	    // Filter for user-defined types (structures, unions, enums, typedefs)  
	    for (DataType dt : allTypes) {  
	        if (dt instanceof Structure || dt instanceof Union ||   
	            dt instanceof Enum || dt instanceof TypeDef) {  
	            myWriter.write("- "+ dt.getName());
	            myWriter.write(System.lineSeparator());
	        }  
	    }  
		
		myWriter.close();
		
	}
}
