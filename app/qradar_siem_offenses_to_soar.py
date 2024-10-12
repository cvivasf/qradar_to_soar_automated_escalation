import requests
import time
import os
import json
from typing import Dict, List
from app_config import ServerConfig, offenses_to_ibm_soar_logger


qradar_headers = {'SEC': None, 'Accept': 'application/json'} #Headers for QRadar API. Paritally obtained from config.ini file
config: ServerConfig = None
available_domains: List[str] = []

def load_last_processed_id()-> int:
    """Load the last processed offense ID from a file.
    
    :return: ID of the last processed offense ID.
    :rtype: int
    :raises OSError,FileNotFoundError,ValueError: if an error occurs when opening/reading the file
    """
    if os.path.exists(config.last_escalated_offense_file):
        with open(config.last_escalated_offense_file, 'r') as file:
            return int(file.read().strip())
    return None

def save_last_processed_id(offense_id:int) -> None:
    """Save the last processed offense ID to a file and updates the script variable
    
    :param int offense_id: The ID of the offense to write on the file as the latest offense processed.
    :return: Nothing.
    :rtype: None
    :raises OSError,FileNotFoundError,ValueError: if an error occurs when opening/writing the file"""
    with open(config.last_escalated_offense_file, 'w') as file:
        file.write(str(offense_id))
    global last_processed_id
    last_processed_id = offense_id

def save_failed_offense_creation_on_soar(offense_id_that_failed:int) -> None:
    """Appends a numeric offense ID the failed SOAR uploaded offenses file, separated by commas.

    :param int offense_id_that_failed: The ID of the offense to write on the Failed Offenses file as the latest offense that failed to be uploaded to IBM SOAR.
    :return: Nothing.
    :rtype: None
    :raises OSError,FileNotFoundError,ValueError: if an error occurs when opening/writing the file"""
    with open(config.failed_escalations_offenses_file, 'a') as file:
        if file.tell() > 0:  # Check if the file is not empty
            file.write(',')
        file.write(str(offense_id_that_failed))

def get_latest_offenses() -> List[Dict[any,any]]:
    #filterout in query the controlled domains

    """Retrieve the latest offense from QRadar. Filtering by status as OPEN, the ID being bigger than the offset ID of the last processed ID from QRADAR, and filtering by start_time in ascendant mode to get the latest one.
    :return: JSON response of the offenses obtained.
    :rtype: Dict[any,any]
    :raises HttpError: if an error occurred making the HTTP request"""

    domains = ",".join(available_domains)  
    params = { "filter": 'status=OPEN and id > ' + str(last_processed_id) + " and domain_id in (" + domains + ")", "sort": "+start_time"  }
    global qradar_headers
    qradar_headers = qradar_headers.copy()
    qradar_headers["RANGE"] = "items=0-0"
    qradar_headers["VERSION"] = "20.0"
    response = requests.get(config.qradar_url, headers=qradar_headers, verify=False, params=params)
    response.raise_for_status()
    return response.json()

def map_severity(severity_quantity):
    '''Maps the SIEM severity with the accepted SOAR severity'''
    try:
        if severity_quantity >= 8 and severity_quantity <= 10:
            return "High"
        if severity_quantity >= 4 and severity_quantity <= 7:
            return "Medium"
        if severity_quantity >= 1 and severity_quantity <= 3:
            return "Low"
    except Exception as e:
        return "Medium"

def get_org_id_from_qradar_domain_and_credentials(offense):
    '''Gets the SOAR org id from the QRADAR domain'''
    if (offense and offense.get("domain_id",-999) > -1):
        for el in config.customer_configurations:
            # print(config.customer_configurations.get(el,{}).get("siem_org_id", ""))
            # print(str(offense.get("domain_id")))
            if str(config.customer_configurations.get(el,{}).get("siem_org_id", "")) == str(offense.get("domain_id")):
                return {"soar_org": config.customer_configurations.get(el,{}).get("soar_org_id", ""), "soar_auth": config.customer_configurations.get(el,{}).get("soar_api_key_auth","")}
        raise Exception ("No domain found on the config.ini file matching the domain of the offense to escalate")
    else:
        raise Exception("No domain ID assigned to the offense")
    
def generate_artifacts(offense):
    '''Generate an array of SOAR artifacts from an offense artifacts'''
    artifacts = []
    if offense:
        if (offense.get("offense_type", -1) in (0, 10)):
            artifacts.append({
                "type": "IP Address",
                "value": offense.get("offense_source",""),
                "description": offense.get("description",""),
                "properties":[
                    {"name": "source", "value": "true"}
                ]
            })
        elif (offense.get("offense_type", -1) in (1, 11)):
             artifacts.append({
                "type": "IP Address",
                "value": offense.get("offense_source",""),
                "description": offense.get("description",""),
                "properties":[
                    {"name": "destination", "value": "true"}
                ]
            })
        elif (offense.get("offense_type", -1) in (3,)):
            artifacts.append({
                "type": "User Account",
                "value": offense.get("offense_source",""),
                "description": offense.get("description",""),
            })
        elif (offense.get("offense_type", -1) in (4,)):
            artifacts.append({
                "type": "MAC Address",
                "value": offense.get("offense_source",""),
                "description": offense.get("description",""),
                "properties":[
                    {"name": "source", "value": "true"}
                ]
            })
        elif (offense.get("offense_type", -1) in (5,)):
            artifacts.append({
                "type": "MAC Address",
                "value": offense.get("offense_source",""),
                "description": offense.get("description",""),
                "properties":[
                    {"name": "destination", "value": "true"}
                ]
            })
        elif (offense.get("offense_type", -1) in (7,)):
            artifacts.append({
                "type": "System Name",
                "value": offense.get("offense_source",""),
                "description": offense.get("description",""),
            })
        elif (offense.get("offense_type", -1) in (8,)):
             artifacts.append({
                "type": "Port",
                "value": offense.get("offense_source",""),
                "description": offense.get("description",""),
                "properties":[
                    {"name": "source", "value": "true"}
                ]
            })
        elif (offense.get("offense_type", -1) in (9,)):
             artifacts.append({
                "type": "Port",
                "value": offense.get("offense_source",""),
                "description": offense.get("description",""),
                "properties":[
                    {"name": "destination", "value": "true"}
                ]
            })
        else:
            artifacts.append({
                "type": "String",
                "value": offense.get("offense_source",""),
                "description": offense.get("description","")
            })
        return artifacts
    else:
        return []

def create_offense_in_soar(offense):
    if (offense):
        soar_mapping = get_org_id_from_qradar_domain_and_credentials(offense)
        # print(soar_mapping)
        body = {
            "discovered_date": offense.get("start_time", int(time.time() * 1000)),
            "description": str(offense.get("event_count", "0")) + " events in " + str(offense.get("category_count", "0")) + " categories: " + offense.get("description"),
            "confirmed": "false",
            "start_date": offense.get("start_time", int(time.time() * 1000)),
            "incident_type_ids": ["System Intrusion"],
            "severity_code": map_severity(offense.get("severity",5)),
            "name": f"QRADAR ID { str(offense.get('id', '0')) } , { offense.get('description', '') } - {offense.get('offense_source', '')}",
            "artifacts": generate_artifacts(offense)
        }

        # print(json.dumps(body))

        headers = {'Accept': 'application/json' , 'Content-Type': 'application/json' , "Authorization": "Basic " + soar_mapping.get("soar_auth","")}
        # print(headers)
        url_=config.soar_url + "/" + soar_mapping.get("soar_org","") + "/incidents"
        # print(url_)
        bod = json.dumps(body)
        # print(bod)
        response = requests.post(url = url_, json = body, headers=headers, verify=False)
        response.raise_for_status()
        return response.json()
    else:
        raise Exception ("Error. No offense to create SOAR incident/case!")

def get_domains_available():
    global available_domains
    for item in config.customer_configurations:
        if config.customer_configurations.get(item,{}).get("siem_org_id"):
            available_domains.append(config.customer_configurations.get(item,{}).get("siem_org_id"))

def process_offense():
    """Process the next unprocessed offense and create a SOAR offense for it."""
    global last_processed_id
    last_processed_id = load_last_processed_id()
    if not last_processed_id:
        raise Exception("ERROR! Provide a minimum Offense ID on the Offense ID index File!")
    
    offenses_to_ibm_soar_logger.info("Last processed Offense ID stored on memory file: " + str(last_processed_id) + " . Getting offense from QRADAR SIEM...")
    latest_offense = get_latest_offenses()
    offenses_to_ibm_soar_logger.info("Call succesfully made to QRADAR SIEM...")
    offenses_to_ibm_soar_logger.debug("Offense to process and send to IBM SOAR: " + json.dumps(latest_offense))
    # Sort offenses by ID in ascending order
    #latest_offense.sort(key=lambda x: x.get('id',None))

    if (not latest_offense or len(latest_offense) == 0):
        offenses_to_ibm_soar_logger.info("No offenses obtained from QRADAR SIEM.")
    #For the first offense obtained, create the SOAR case and update the file containing the last processed ID.
    for offense in latest_offense:
        offense_id = offense.get('id', None)
        if last_processed_id is not None and offense_id > last_processed_id:
            offenses_to_ibm_soar_logger.info(f"Processing offense with ID. About to create it on SOAR!: {offense_id}")
            try:
                create_offense_in_soar(offense)
                save_last_processed_id(offense_id)
                pass
            except Exception as e:
                offenses_to_ibm_soar_logger.error(f"Exception creating SOAR incident for offense with ID: {str(offense_id)}: {str(e)}")
                save_failed_offense_creation_on_soar(offense_id) #store the failed offense to be uploaded to soar in a file
            break #Process only one offense at a time
        else:
            offenses_to_ibm_soar_logger.error(f"Offense {offense_id} has already been processed. Please, increase the Offense ID offset on the file to start scanning new offenses!.")

def init_vars(passedconfig: ServerConfig):
    '''
    Initializates variables for the script

    :param int passedconfig: Configuration received from the config.ini file
    :return: None
    :rtype: None
    '''
    global config
    config = passedconfig
    global qradar_headers
    qradar_headers = {'SEC': config.qradar_api_key, 'Accept': 'application/json'}

def main(passedconfig: ServerConfig):
    
    init_vars(passedconfig)

    """Main loop to continuously check for new offenses and process them."""
    while True:
        try:
            get_domains_available()
            process_offense()
        except Exception as e:
            offenses_to_ibm_soar_logger.error(f"Error pulling and/or sending offenses to IBM SOAR from QRADAR SIEM Offenses obtention: {str(e)}")
        time.sleep(config.polling_rate_new_offenses_checking)

if __name__ == "__main__":
    main()