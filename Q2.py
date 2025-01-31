
import subprocess
import argparse
import os

# Set up for command-line argument
p1 = argparse.ArgumentParser(description='Create a .img file from the given file.')
p1.add_argument('input', type=str, help='Path to input directory')
p1.add_argument('output', type=str, help='Path to output directory')
p1.add_argument('filetype', type=str, help='Type of files to process (e.g., jpg, pdf,jpeg,mov, etc.)')
args = p1.parse_args()

# Resolve full paths
input_path = os.path.abspath(args.input)
output_path = os.path.abspath(args.output)

# Check whether the directories exist
if not os.path.isdir(input_path):
    print(f"ERROR: Input directory '{input_path}' does not exist.")
    exit(1)
if not os.path.isdir(output_path):
    print(f"ERROR: Output directory '{output_path}' does not exist.")
    exit(1)

# Check and process files with the given filetype
filetype = args.filetype
files_to_process = [f for f in os.listdir(input_path) if f.endswith(f".{filetype}")]

if not files_to_process:
    print(f"ERROR: No files with the '.{filetype}' extension found in '{input_path}'.")
    exit(1)

for filename in files_to_process:
    input_file = os.path.join(input_path, filename)
    output_file = os.path.join(output_path, f"{filename}.img")

    # Construct the dd command
    command = f"sudo dd if={input_file} of={output_file} status=progress"

    # Execute the command
    try:
        print(f"Processing file: {input_file}")
        subprocess.run(command, shell=True, check=True)
        print(f"Image created successfully at '{output_file}'.")
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to process '{input_file}' with exit code {e.returncode}.")
        print("Version3")




