//Creates notes for user defined data types
//@author Kai Jun
//@category 
//@keybinding
//@menupath
//@toolbar

import java.io.File;
import java.io.FileWriter;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.plugin.core.navigation.locationreferences.LocationReference;
import ghidra.app.plugin.core.navigation.locationreferences.ReferenceUtils;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.FieldMatcher;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.util.datastruct.ListAccumulator;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;

public class DataTypesNoteTaker extends GhidraScript {

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
		
		DataTypeManager dataTypeManager = currentProgram.getDataTypeManager();
		
		Category myTypes = dataTypeManager.getCategory(new CategoryPath("/myTypes"));
		DataType[] dataTypes = myTypes.getDataTypes();
		
		for (DataType dt : dataTypes) {
			int dtSize = dt.getLength();
			
			FileWriter myWriter = new FileWriter(directory.getPath() + "/" + dt.getName() + ".md");
			myWriter.write("---");
			myWriter.write(System.lineSeparator());
			myWriter.write("aliases:");
			myWriter.write(System.lineSeparator());
			myWriter.write("  - " + dt.getName());
			myWriter.write(System.lineSeparator());
			myWriter.write("size: \"0x" + Integer.toHexString(dtSize) + "\"");
			myWriter.write(System.lineSeparator());
		
			ListAccumulator<LocationReference> accumulator = new ListAccumulator<>();
			ReferenceUtils.findDataTypeFieldReferences(accumulator, new FieldMatcher(dt), currentProgram, true, null);
			List<LocationReference> references = accumulator.asList();
			myWriter.write("called by:");
			myWriter.write(System.lineSeparator());
			
			Set<Function> referencingFunctions = new HashSet<>();
			
			for (LocationReference ref : references) {
				Address refAddress = ref.getLocationOfUse();
				Function function = getFunctionContaining(refAddress);
				if (function != null) {
					if(!referencingFunctions.contains(function)) {
						referencingFunctions.add(function);
						myWriter.write("  - " + function.getName());
						myWriter.write(System.lineSeparator());
					}
				}
			}
			
			if (dt instanceof ghidra.program.model.data.Enum) {
				myWriter.write("tags:");
				myWriter.write(System.lineSeparator());
				myWriter.write("  - Enum");
				myWriter.write(System.lineSeparator());
				
				myWriter.write("---");
				myWriter.write(System.lineSeparator());
				
				String description = dt.getDescription();
				if(!description.isEmpty()) {
					myWriter.write("Description:");
					myWriter.write(System.lineSeparator());
					myWriter.write(description);
					myWriter.write(System.lineSeparator());
					myWriter.write(System.lineSeparator());
				}
				
			    myWriter.write("Name | Value | Comment");
			    myWriter.write(System.lineSeparator());
			    myWriter.write("--- | --- | ---");
			    myWriter.write(System.lineSeparator());
			    
			    String[] names = ((ghidra.program.model.data.Enum)dt).getNames();
			    
			    for (String name : names) {
			    	long value = ((ghidra.program.model.data.Enum)dt).getValue(name);
			    	String comment = ((ghidra.program.model.data.Enum)dt).getComment(name);
			    	
			    	myWriter.write(name + " | 0x" + Long.toHexString(value) + " | " + comment);
			    	myWriter.write(System.lineSeparator());
			    }
			}
			else if (dt instanceof Structure) {
				myWriter.write("tags:");
				myWriter.write(System.lineSeparator());
				myWriter.write("  - struct");
				myWriter.write(System.lineSeparator());

				myWriter.write("---");
				myWriter.write(System.lineSeparator());
				String description = dt.getDescription();
				if(!description.isEmpty()) {
					myWriter.write("Description:");
					myWriter.write(System.lineSeparator());
					myWriter.write(description);
					myWriter.write(System.lineSeparator());
					myWriter.write(System.lineSeparator());
				}
				
			    DataTypeComponent[] definedComponents = ((Structure)dt).getDefinedComponents();
			    if (definedComponents.length == 0) {
			    	continue;
			    }
			    
			    myWriter.write("Offset | DataType | Length | Name | Comment");
			    myWriter.write(System.lineSeparator());
			    myWriter.write("--- | --- | --- | --- | ---");
			    myWriter.write(System.lineSeparator());
			    for (DataTypeComponent dtc : definedComponents) {  
				    myWriter.write("0x" + Integer.toHexString(dtc.getOffset()) + " | " + dtc.getDataType().getName() + " | 0x" + Integer.toHexString(dtc.getLength()) + " | " + (dtc.getFieldName() != null ? dtc.getFieldName() : "unnamed") + " | " + dtc.getComment());
				    myWriter.write(System.lineSeparator());
			    }  
				
			}
			myWriter.close();
		}
		
	}
}
