import os
import json
from block_crypting import BlockCrypting
from custom_modes import CustomModes

def read_gif(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

def write_gif(file_path, data):
    with open(file_path, 'wb') as file:
        file.write(data)

def run_test(config_file,input_file, output_folder):
    with open(config_file, 'r') as file:
        config = json.load(file)
        
    data = read_gif(input_file)   
        
    block_crypting = BlockCrypting(config_file)
    
    algorithm = config["algorithm"]
    mode = config["mode"]
    
    encrypted_data = block_crypting.encrypt(data)
    
    decrypted_data = block_crypting.decrypt(encrypted_data)
    
    output_decrypted_file = os.path.join(output_folder, f"output-{algorithm}-{mode}-decrypted.gif")
    write_gif(output_decrypted_file, decrypted_data)
    # print(f"Decrypted file written to {output_decrypted_file}")

def main():
    output_folder = "output"
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    input_file = "./input/input.gif"
    
    config_files = [
        "./config/config1.json", 
        "./config/config2.json", 
        "./config/config3.json", 
        "./config/config4.json", 
        "./config/config5.json", 
        "./config/custom_config1.json", 
        "./config/custom_config2.json", 
        "./config/custom_config3.json", 
        "./config/custom_config4.json", 
        "./config/custom_config5.json"
    ]

    # Run tests for each configuration
    for config_file in config_files:
        print(f"Running test with config: {config_file}")
        run_test(config_file,input_file, output_folder)

if __name__ == "__main__":
    main()
