import configparser
from typing import List

def is_valid_section(section_data):
    """Check if the section has valid values for soar_api_id, soar_api_key, and soar_org_id."""
    try:
        soar_api_id = section_data.get('soar_api_id')
        soar_api_key = section_data.get('soar_api_key')
        
        try:
            soar_org_id = int(section_data.get('soar_org_id'))  # Ensure it's an integer
        except Exception:
            soar_org_id = -1

        # Validate that soar_api_id and soar_api_key are non-empty strings
        # and soar_org_id is a positive integer.
        if isinstance(soar_api_id,str) and soar_api_id.strip() != "" and isinstance(soar_api_key,str) and \
            soar_api_key.strip() != "" and isinstance(soar_org_id, int) and soar_org_id >= 0:
            #return {"soar_api_id": soar_api_id, "soar_api_key":soar_api_key, "soar_org_id" : soar_org_id }
            return True
        else:
            print("Not a valid section data")
    except (ValueError, configparser.NoOptionError):
        print("Exception with section")
        return False  # Return false if any required option is missing or invalid
    
    return False

def filter_valid_sections(config):

    valid_sections = {}

    sections: List[str] = config.sections()
    # Iterate over all sections
    for section in sections:
        customer_name = section.replace("Customer_", "", 1)
        # Filter sections that start with 'Customer_'
        if section.startswith('Customer_'):
            if bool(customer_name.strip()):
                customer_name = section.replace("Customer_", "", 1)
                section_data = dict(config.items(section))           
                # Check if the section is valid
                if is_valid_section(section_data):
                    valid_sections[section] = dict(section_data)
                else:
                    print(f"Section {section} had invalid data. Customer section will be ommited and offenses might not be escalated for such customer.")
            else:
                print(f"Skipping section {section} due not being a Customer_ section or having an empty customer name.")

    return valid_sections

def get_customer_domains(customer_configs:dict[str,dict[any]]):
    customer_names = []
    if customer_configs:
        pass
        for key in customer_configs.keys():
            print(key)
            customer_name = key.split("Customer_",1)[1].strip()
            print(customer_name)
            try:
                found = customer_names.index(customer_name,0)
            except ValueError:
                customer_names.append(customer_name)
        return customer_names
    else:
        return []

def main():
    '''Initializes ServerConfig object to be used by app modules by using the config.ini file and the configparser module.

    :return: ServerConfig object with the configuration for the app
    :rtype: ServerConfig'''
    #Read the configuration file
    print('[QRadar2IBM_SOAR_automated_escalation] Building App configparser...')
    config = configparser.ConfigParser()
    print('[QRadar2IBM_SOAR_automated_escalation] Reading config.ini file...')
    config.read('config.ini')
    print('[QRadar2IBM_SOAR_automated_escalation] Config.ini file read succesfully!...')
    #Get customer config and customer domains
    customer_config_sections = filter_valid_sections(config)
    customer_names = get_customer_domains(customer_config_sections)
    print (customer_config_sections)
    print(customer_names)

if __name__ == "__main__":
    main()