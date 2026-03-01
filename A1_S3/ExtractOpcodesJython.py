#A custom script used to send malware to the selected code-reversing tool.
#@author MJ
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython


import os

# Your exact directory path
out_dir = "/home/remnux/Desktop/A1_S3_Malware/opcodes"
if not os.path.exists(out_dir):
    os.makedirs(out_dir)

print("Extracting opcodes to: " + out_dir)

# Get current program
program = getCurrentProgram()

if program is None:
    print("ERROR: No program open! Click a binary tab first.")
else:
    # Create output filename
    name = program.getName()
    output_file = os.path.join(out_dir, name + ".opcode")
    
    print("Processing: " + name)
    
    # Extract opcodes
    f = open(output_file, 'w')
    f.write("FILE: " + name + "\n")
    
    listing = program.getListing()
    instructions = listing.getInstructions(True)
    
    count = 0
    for instruction in instructions:
        try:
            mnemonic = instruction.getMnemonicString()
            f.write(mnemonic + "\n")
            count += 1
        except:
            continue
    
    f.close()
    
    print("SUCCESS: " + str(count) + " opcodes saved to:")
    print(output_file)

print("Check: " + out_dir)